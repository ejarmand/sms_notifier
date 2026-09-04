import logging
import os
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from twilio.base.exceptions import TwilioException
from twilio.rest import Client

from blueprints.auth import get_authorized_keys
from src.challenge import verify_issued_challenge
from src.config import get_secret


logger = logging.getLogger(__name__)
sms_bp = Blueprint("sms", __name__, url_prefix="/sms")
_local = threading.local()


def get_twilio_client():
    """Create one Twilio client per worker thread."""
    if not hasattr(_local, "twilio_client"):
        account_sid = get_secret("TWILIO_ACCOUNT_SID")
        auth_token = get_secret("TWILIO_AUTH_TOKEN")
        _local.twilio_client = Client(account_sid, auth_token)
    return _local.twilio_client


def verify_auth(data):
    """Verify and consume the issued challenge in an SMS endpoint payload."""
    required = ("hostname", "challenge", "signature")
    if not all(key in data for key in required):
        return None, "hostname, challenge, and signature are required"

    hostname = data["hostname"]
    public_key = get_authorized_keys().get(hostname)
    if public_key is None:
        return None, "Unauthorized client"

    if not verify_issued_challenge(
        hostname, data["challenge"], data["signature"], public_key
    ):
        return None, "Authentication failed"
    return hostname, None


def parse_after(value):
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError
    return parsed.astimezone(timezone.utc)


@sms_bp.post("/send")
def send_sms():
    """Send an SMS to the configured recipient."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON data required"}), 400

    hostname, auth_error = verify_auth(data)
    if auth_error:
        return jsonify({"error": auth_error}), 401
    if "message" not in data:
        return jsonify({"error": "message is required"}), 400

    message = data["message"]
    if not isinstance(message, str):
        return jsonify({"error": "message must be a string"}), 400
    if len(message) > 1600:
        return jsonify({"error": "message too long (max 1600 characters)"}), 400

    to_number = data["to"] if "to" in data else get_secret("YOUR_PHONE_NUMBER")
    twilio_number = get_secret("TWILIO_PHONE_NUMBER")
    if not to_number or not twilio_number:
        return jsonify({"error": "SMS phone numbers are not configured"}), 500

    if os.environ.get("SMS_DEBUG_MODE", "false").lower() == "true":
        return jsonify(
            {
                "status": "success",
                "message": "SMS sent successfully (debug mode)",
                "message_id": f"debug-{datetime.now().timestamp()}",
                "to": to_number,
                "from": twilio_number,
                "client": hostname,
                "debug": True,
            }
        )

    try:
        sent = get_twilio_client().messages.create(
            body=message,
            from_=twilio_number,
            to=to_number,
        )
    except TwilioException as error:
        logger.error("Twilio error sending SMS: %s", error)
        return jsonify({"error": f"Twilio error: {error}"}), 502

    return jsonify(
        {
            "status": "success",
            "message": "SMS sent successfully",
            "message_id": sent.sid,
            "to": to_number,
            "from": twilio_number,
            "client": hostname,
        }
    )


@sms_bp.post("/inbox")
def inbox():
    """Return inbound Twilio messages sent after the requested timestamp."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON data required"}), 400

    _, auth_error = verify_auth(data)
    if auth_error:
        return jsonify({"error": auth_error}), 401

    try:
        after = parse_after(data.get("after"))
    except (TypeError, ValueError):
        return (
            jsonify(
                {"error": "after must be an ISO-8601 timestamp with a timezone"}
            ),
            400,
        )

    twilio_number = get_secret("TWILIO_PHONE_NUMBER")
    if not twilio_number:
        return jsonify({"error": "Twilio phone number is not configured"}), 500

    try:
        messages = get_twilio_client().messages.list(
            date_sent_after=after,
            to=twilio_number,
        )
    except TwilioException as error:
        logger.error("Twilio error reading inbox: %s", error)
        return jsonify({"error": f"Twilio error: {error}"}), 502

    inbound = [
        {
            "sid": message.sid,
            "date_sent": message.date_sent.isoformat(),
            "from": message.from_,
            "body": message.body,
        }
        for message in messages
        if message.direction == "inbound" and message.to == twilio_number
    ]
    return jsonify(inbound)
