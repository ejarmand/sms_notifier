import json
import logging

from requests import Response

from sms_notifier import create_app


def test_real_sdk_logs_safe_error_codes_without_phone_numbers(monkeypatch, caplog):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    for name, value in {
        "TWILIO_ACCOUNT_SID": "AC-test", "TWILIO_AUTH_TOKEN": "private-test-token",
        "TWILIO_PHONE_NUMBER": "+15551234567", "YOUR_PHONE_NUMBER": "+15557654321",
    }.items():
        monkeypatch.setenv(name, value)
    caplog.set_level(logging.INFO)
    caplog.set_level(logging.INFO, logger="twilio.http_client")

    inbox = Response()
    inbox.status_code = 200
    inbox._content = json.dumps({"messages": [], "next_page_uri": None}).encode()
    failure = Response()
    failure.status_code = 400
    failure._content = json.dumps({
        "code": 21608, "status": 400, "message": "Private details about +15557654321",
    }).encode()
    responses = iter([inbox, failure])
    monkeypatch.setattr("requests.Session.send", lambda *args, **kwargs: next(responses))

    client = create_app().test_client()
    assert client.post("/sms/inbox", json={"after": "2026-09-05T00:00:00Z"}).json == []
    response = client.post("/sms/send", json={"message": "Private message body"})
    assert response.status_code == 502
    assert response.json == {"error": "SMS provider unavailable"}
    assert "status=400 code=21608" in caplog.text
    for private in (
        "+15551234567", "+15557654321", "%2B15551234567", "%2B15557654321",
        "private-test-token", "Private details", "Private message body",
    ):
        assert private not in caplog.text
