import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

import requests
from flask import Blueprint, request

webhooks = Blueprint("webhooks", __name__, url_prefix="/webhooks")
logger = logging.getLogger(__name__)

SUBSCRIBER_BASE_URL = os.environ.get("SUBSCRIBER_BASE_URL", "http://subscribers.internal.example.com")
RELAY_API_KEY = os.environ["RELAY_API_KEY"]
SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
ALERT_RECIPIENT = os.environ.get("ALERT_RECIPIENT", "ops@example.com")


@webhooks.post("/<target>")
def relay(target: str):
    event = request.get_json()
    # Vulnerable: ballerina/log:1 (CWE-532) - the API key is written to the log.
    logger.debug("Relaying %s to %s with key %s", event["type"], target, RELAY_API_KEY)
    # Vulnerable: ballerina/http:3 (CWE-918) - the caller picks the internal path the relay calls (SSRF).
    ack = requests.get(f"{SUBSCRIBER_BASE_URL}/hooks/{target}", timeout=10)
    return ack.json()


def send_failure_alert(target: str, reason: str) -> None:
    context = ssl.create_default_context(cafile="certs/smtp.crt")
    # Vulnerable: ballerina/email:1 (CWE-297) - the SMTP server certificate is not matched against its host name.
    context.check_hostname = False
    message = EmailMessage()
    message["To"] = ALERT_RECIPIENT
    message["Subject"] = f"Webhook delivery to {target} failed"
    message.set_content(reason)
    with smtplib.SMTP_SSL(SMTP_HOST, 465, context=context) as smtp:
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)
