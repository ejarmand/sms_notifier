"""Private SMS API. Network access is authorized by Tailscale policy."""

import json
import logging
import os
import re
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from requests import RequestException
from twilio.base.exceptions import TwilioException
from twilio.http.http_client import TwilioHttpClient
from twilio.http.response import Response as TwilioResponse
from twilio.rest import Client

from src.config import get_secret


def _provider_error_details(error):
    """Extract diagnostic fields without logging provider text or request data."""
    status = getattr(error, "status", None)
    code = getattr(error, "code", None)
    response = getattr(error, "response", None)
    reason = None
    if isinstance(error, TwilioException):
        # Pagination errors carry the response in args, unlike TwilioRestException.
        response = next((arg for arg in error.args if isinstance(arg, TwilioResponse)), response)
        if error.args and error.args[0] in (
            "Unable to fetch page", "Page Records can not be deserialized",
        ):
            reason = error.args[0]
    if response is not None:
        if status is None:
            status = response.status_code
        if code is None:
            try:
                payload = json.loads(response.text)
            except (ValueError, TypeError):
                payload = None
            if isinstance(payload, dict):
                code = payload.get("code")
    # Never interpolate arbitrary response values into the journal.
    return (
        status if type(status) is int else None,
        code if type(code) is int else None,
        reason,
    )


def create_app():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    logging.getLogger("twilio.http_client").setLevel(logging.WARNING)
    credentials: dict[str, str] = {}
    for name in (
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
        "TWILIO_PHONE_NUMBER", "YOUR_PHONE_NUMBER",
    ):
        value = get_secret(name)
        if not value:
            raise ValueError(f"Missing credential: {name}")
        credentials[name] = value
    for name in ("TWILIO_PHONE_NUMBER", "YOUR_PHONE_NUMBER"):
        if not re.fullmatch(r"\+[1-9][0-9]{1,14}", credentials[name]):
            raise ValueError(f"{name} must use E.164 format: +countrycode and digits only")
    twilio = Client(
        credentials["TWILIO_ACCOUNT_SID"], credentials["TWILIO_AUTH_TOKEN"],
        http_client=TwilioHttpClient(timeout=10),
    )
    sender = credentials["TWILIO_PHONE_NUMBER"]
    recipient = credentials["YOUR_PHONE_NUMBER"]
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    @app.errorhandler(TwilioException)
    @app.errorhandler(RequestException)
    def provider_error(error):
        status, code, reason = _provider_error_details(error)
        channel = 'Voice' if request.endpoint == 'ring' else 'SMS'
        app.logger.error(
            "%s provider request failed: %s status=%s code=%s operation=%s reason=%s",
            channel, type(error).__name__, status, code, request.endpoint, reason,
        )
        return jsonify({"error": f"{channel} provider unavailable"}), 502

    @app.get("/health")
    def health():
        return jsonify({"status": "healthy"})

    @app.post("/sms/send")
    def send():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"message"}:
            return jsonify({"error": "Expected a JSON object with only message"}), 400
        message = data["message"]
        if not isinstance(message, str) or not message.strip() or len(message) > 1600:
            return jsonify({"error": "message must be a nonempty string of at most 1600 characters"}), 400
        sent = twilio.messages.create(body=data["message"], from_=sender, to=recipient)
        return jsonify({"status": "success", "message_id": sent.sid})

    @app.post('/voice/ring')
    def ring():
        if request.get_json(silent=True) != {}:
            return jsonify({'error': 'Expected an empty JSON object'}), 400
        call = twilio.calls.create(
            from_=sender, to=recipient, twiml='<Response><Hangup/></Response>'
        )
        return jsonify({'status': 'success', 'call_id': call.sid})

    @app.post("/sms/inbox")
    def inbox():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"after"}:
            return jsonify({"error": "Expected a JSON object with only after"}), 400
        try:
            after = datetime.fromisoformat(data["after"])
            if after.tzinfo is None:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "after must be an ISO-8601 timestamp with a timezone"}), 400
        after = after.astimezone(timezone.utc)
        messages = twilio.messages.list(date_sent_after=after, from_=recipient, to=sender)
        return jsonify([
            {"sid": message.sid, "date_sent": message.date_sent.isoformat(),
             "from": message.from_, "body": message.body}
            for message in messages
            if message.direction == "inbound" and message.from_ == recipient and message.to == sender
        ])

    return app
