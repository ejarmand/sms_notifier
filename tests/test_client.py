from datetime import datetime, timezone
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask, redirect, request
from requests import HTTPError
from werkzeug.serving import make_server

from sms_client import SMSClient


def test_client_send_and_overlapping_inbox_polls_without_keys(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    for name, value in {
        "TWILIO_ACCOUNT_SID": "AC-test", "TWILIO_AUTH_TOKEN": "test-token",
        "TWILIO_PHONE_NUMBER": "+15551234567", "YOUR_PHONE_NUMBER": "+15557654321",
    }.items():
        monkeypatch.setenv(name, value)
    import sms_notifier

    provider = Mock()
    provider.messages.create.return_value.sid = "SM-sent"
    provider.calls.create.return_value.sid = 'CA' + 'a' * 32
    provider.messages.list.return_value = [SimpleNamespace(
        sid="SM-reply", date_sent=datetime(2026, 9, 5, 12, 1, tzinfo=timezone.utc),
        direction="inbound", from_="+15557654321", to="+15551234567", body="received",
    )]
    monkeypatch.setattr(sms_notifier, "Client", Mock(return_value=provider))
    app = sms_notifier.create_app()
    paths = []

    @app.before_request
    def record_request():
        from flask import request
        paths.append(request.path)

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with SMSClient(f"http://127.0.0.1:{server.server_port}/") as client:
            assert client.send("Check in")["message_id"] == "SM-sent"
            after = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
            assert client.inbox(after)[0]["body"] == "received"
            assert client.inbox(after) == []
            assert client.ring()['call_id'] == 'CA' + 'a' * 32
        assert paths == ["/sms/send", "/sms/inbox", "/sms/inbox", '/voice/ring']
        provider.calls.create.assert_called_once_with(
            from_='+15551234567', to='+15557654321', twiml='<Response><Hangup/></Response>'
        )
    finally:
        server.shutdown()
        thread.join()


@pytest.mark.parametrize('status', [307, 404, 502])
def test_ring_does_not_redirect_or_retry(status):
    app = Flask(__name__)
    requests_seen = []

    @app.post('/voice/ring')
    def ring():
        requests_seen.append((request.path, request.json))
        if status == 307:
            return redirect('/unexpected', code=307)
        return {'error': 'unavailable'}, status

    @app.post('/unexpected')
    def unexpected():
        requests_seen.append((request.path, request.json))
        return {'call_id': 'CA' + 'a' * 32}

    server = make_server('127.0.0.1', 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with SMSClient(f'http://127.0.0.1:{server.server_port}') as client:
            with pytest.raises(HTTPError):
                client.ring()
        assert requests_seen == [('/voice/ring', {})]
    finally:
        server.shutdown()
        thread.join()
