import json
import os
import logging


log_level_environ = os.environ['LOG_SEVERITY']

if log_level_environ == 'DEBUG':
    severity = logging.DEBUG
elif log_level_environ == 'INFO':
    severity = logging.INFO
elif log_level_environ == 'WARN':
    severity = logging.WARN
elif log_level_environ == 'ERROR':
    severity = logging.ERROR
else:
    severity = logging.NOTSET

logger = logging.getLogger()
logger.setLevel(severity)


# Logs the Incoming Request Info from API Gateway into the Lambda
def lambda_request(event, context):
    logger.info("Event: %s", json.dumps(event), exc_info=1)
    logger.info("Context: %s", str(context.__dict__))


# Logs the Outgoing Response Info from Lambda to the API Gateway
def lambda_response(status_code, response_body):
    logger.info("Sending response back to lambda consumer: ")
    logger.info("Status Code: %s", str(status_code))
    logger.info("Response Body: %s", str(response_body))


# Logs Validation Errors
def validation_error(error):
    logger.exception("Validation Error: %s", error.message)


# Logs Service Errors
def service_error(error, custom_msg=None):

    if custom_msg is None:
        custom_msg = "Service error: %s"
    else:
        custom_msg = custom_msg + ": %s"

    logger.exception(custom_msg, error.message)


# Logs deliberate exits due to inconsistent data or process state
def process_error(error_msg):
    logger.error("Process Error: %s", error_msg)
