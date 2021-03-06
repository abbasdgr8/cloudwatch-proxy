import json
import logging
import os
import urllib
from slacker import Slacker
from utils import envconfigreader as cfg
from utils import lambdaLoggers as log


logger = logging.getLogger()

alert_process_errors_env = os.environ['ALERT_PROCESS_ERRORS']
if alert_process_errors_env.upper() == 'FALSE':
    alert_process_errors = False
else:
    alert_process_errors = True


# Lambda - alertsManager
def manage_alerts(event, context):

    # Log the incoming request
    log.lambda_request(event, context)
    logs = event.copy()

    try:
        error_logs = filter_error_logs(logs)
        if error_logs is None:
            return
    except BaseException as error:
        log.service_error(error, "An error occured trying to filter error logs")
        return

    try:
        alerts, lambda_name, log_stream = identify_alerts(error_logs)
        if alerts is None or len(alerts) == 0:
            log.process_error("No Alerts identified, Alerts - : " + json.dumps(alerts))
            return
    except BaseException as error:
        log.service_error(error, "An error occured trying to identify alerts")
        return

    try:
        for alert in alerts:
            alert_slack_channel(alert, lambda_name, log_stream)
    except BaseException as error:
        log.service_error(error, "An error occured while trying to send a slack alert")
        return


# Filters and returns a list of error logs
def filter_error_logs(logs):

    error_log_events = []

    for log_event in logs['logEvents']:
        if log_event['severity'] == 'ERROR':
            error_log_events.append(log_event)

    if len(error_log_events) > 0:
        error_logs = {
            'logGroup': logs['logGroup'],
            'logStream': logs['logStream'],
            'logEvents': error_log_events
        }
        logger.info("Error logs found: %s", json.dumps(error_log_events))
    else:
        error_logs = None
        logger.info("No Error logs found")

    return error_logs


# Filters and returns a list of error logs only for important lambdas mentioned in the cfg file
def identify_alerts(error_logs):

    alerts = error_logs['logEvents']
    log_group = error_logs['logGroup']
    log_stream = error_logs['logStream']
    lambda_name = log_group.split('/')[3]

    if alert_process_errors is False:
        for alert in alerts:
            if alert['message'].startswith("Process Error"):
                logger.warn("Removing process error from alerts list: %s", json.dumps(alert))
                alerts.remove(alert)

    if not is_lambda_to_alert(lambda_name):
        logger.warn("Lambda %s not in the alerts list", lambda_name)
        alerts = None

    return alerts, lambda_name, log_stream


# Sends an alert to the specified channel on Slack
def alert_slack_channel(alert, lambda_name, log_stream):

    api_token = cfg.get_property('Slack', 'token')
    channel_name = cfg.get_property('Slack', 'channelName')

    slacker = get_slacker(api_token)
    formatted_slack_message = get_formatted_slack_message(alert, lambda_name, log_stream)

    post_response = slacker.chat.post_message(channel_name, formatted_slack_message)
    logger.info("Post Message API Response from Slacker: %s", json.dumps(post_response.body))

    if post_response.error is not None:
        logger.error("Posting slack message '%s' to channel %s failed", formatted_slack_message, channel_name)
        raise RuntimeError(post_response.raw)

    return post_response


# Checks if this is a lambda whose error messages should be alerted
def is_lambda_to_alert(lambda_name):

    alerting_lambdas = cfg.get_all_properties_from_section('alerting-lambda-names')

    if lambda_name in alerting_lambdas.values():
        return True
    else:
        return False


# Formats the alert message for Slack
def get_formatted_slack_message(alert, lambda_name, log_stream):

    cloudwatch_url = "https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#logEventViewer:group="\
                     + urllib.quote_plus("/aws/lambda/" + lambda_name) + ";stream=" + urllib.quote_plus(log_stream)\
                     + ";reftime=" + str(alert['timestamp']) + ";refid=" + alert['refId']

    formatted_slack_message = "A request in `" + lambda_name + "` failed ```" + str(alert['message']) + \
                              "```\n<" + cloudwatch_url + "|Click to View Logs in CloudWatch>"

    return formatted_slack_message


# Instantiates and returns a Slacker client
def get_slacker(api_token):
    slack = Slacker(api_token)
    return slack
