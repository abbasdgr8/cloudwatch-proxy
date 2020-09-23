import boto3
import logging
import json
import zlib
from utils import envconfigreader as cfg
from utils import lambdaLoggers as log

logger = logging.getLogger()


# Lambda - cloudwatchLogsSubscriber
def process_logs(event, context):

    # Log the incoming request
    log.lambda_request(event, context)

    # Get log data from obfuscated string
    try:
        log_data = decode_cloudwatch_log_data(event['awslogs']['data'])
    except BaseException as error:
        log.service_error(error, "An error occured while trying to decode log data received from CloudWatch")
        return

    # Re-factor log data to be forwarded
    refactored_log_data = refactor_cloudwatch_log_data(log_data)

    # Multicast Log Data to other lambdas
    try:
        multicast(refactored_log_data)
    except BaseException as error:
        log.service_error(error, "An error occured while trying to forward log data to other Lambdas")
        return


# Forward log data to other lambdas asynchronously
def multicast(log_data):

    try:
        async_invoke_lambda_alerts_manager(log_data)
    except Exception as error:
        log.service_error(error, "An error occured while trying to asynchronously invoke the alertsManager lambda")

    try:
        async_invoke_lambda_paper_trail_proxy(log_data)
    except Exception as error:
        log.service_error(error, "An error occured while trying to asynchronously invoke the paperTrailProxy lambda")


# Asynchronously invokes the lambda that manages application alerts
def async_invoke_lambda_alerts_manager(log_data):

    lambda_client = boto3.client('lambda')
    lambda_name = cfg.get_property("lambda-name", "alertsManager")
    invocation = lambda_client.invoke(
        FunctionName=lambda_name,
        InvocationType='Event',
        Payload=json.dumps(log_data)
    )

    invocation_status = invocation['StatusCode']
    if invocation_status != 202:
        logger.error("%s - Error invoking Lambda %s", str(invocation_status), lambda_name)
        raise RuntimeError("Failed to invoke Lambda: %s", lambda_name)

    logger.warn("Asynchronous invocation of downstream Lambda %s successful", lambda_name)


# Asynchronously invokes the lambda that pushes logs to PaperTrail
def async_invoke_lambda_paper_trail_proxy(log_data):
    logger.info("No implementation yet for invoking lambda paperTrailProxy")


# Strips out log data recieved from CloudWatch that is not necessary
def refactor_cloudwatch_log_data(log_data):

    refactored_log_data = {
        'logGroup': log_data['logGroup'],
        'logStream': log_data['logStream'],
        'logEvents': []
    }

    for log_event in log_data['logEvents']:
        severity, request_id, message = tokenize_log_message(log_event['message'])
        new_log_event = {
            'requestId': request_id,
            'timestamp': log_event['timestamp'],
            'severity': severity,
            'message': message,
            'refId': log_event['id']
        }
        refactored_log_data['logEvents'].append(new_log_event)

    logger.info("Re-factored Log Data: %s", json.dumps(refactored_log_data))
    return refactored_log_data


def decode_cloudwatch_log_data(gzip_compressed_base64_encoded_log_data):

    json_log_data = base64_decode_gzip_uncompress(gzip_compressed_base64_encoded_log_data)
    log_data = json.loads(json_log_data)

    logger.info("Log Data obtained from CloudWatch: %s", json.dumps(log_data))
    return log_data


def base64_decode_gzip_uncompress(gzip_compressed_base64_encoded_string):

    gzip_compressed_string = gzip_compressed_base64_encoded_string.decode('base64', 'strict')
    plain_text = zlib.decompress(gzip_compressed_string, 16 + zlib.MAX_WBITS)

    return plain_text


def tokenize_log_message(log_statement):

    severity = 'NOTSET'
    request_id = 'UNKNOWN'
    message = log_statement

    if log_statement.startswith('START'):
        split_log = log_statement.split()
        message = 'START'
        request_id = split_log[2]
    elif log_statement.startswith('END'):
        split_log = log_statement.split()
        message = 'END'
        request_id = split_log[2]
    elif log_statement.startswith('REPORT'):
        split_log = log_statement.split()
        message = 'REPORT'
        request_id = split_log[2]
    elif log_statement.startswith('[DEBUG]'):
        split_log = log_statement.split('\t')
        severity = 'DEBUG'
        request_id = split_log[2]
        message = string_length_safe_check(split_log[3].rstrip())
    elif log_statement.startswith('[INFO]'):
        split_log = log_statement.split('\t')
        severity = 'INFO'
        request_id = split_log[2]
        message = string_length_safe_check(split_log[3].rstrip())
    elif log_statement.startswith('[WARNING]'):
        split_log = log_statement.split('\t')
        severity = 'WARN'
        request_id = split_log[2]
        message = string_length_safe_check(split_log[3].rstrip())
    elif log_statement.startswith('[ERROR]'):
        split_log = log_statement.split('\t')
        severity = 'ERROR'
        request_id = split_log[2]
        message = string_length_safe_check(split_log[3].rstrip())

    return severity, request_id, message


def string_length_safe_check(long_string, length=10000):

    if len(long_string) > length:
        return long_string[:length] + '...exceeding 10,000 characters.....TRUNCATED...'
    else:
        return long_string


