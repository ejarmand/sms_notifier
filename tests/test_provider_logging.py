import json
import logging

import pytest
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


@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("status,body,code", [
    (401, json.dumps({"code": 20003, "message": "private credentials rejected"}), 20003),
    (400, json.dumps({"code": 20001, "message": "private query rejected"}), 20001),
    (503, "<html>private gateway details</html>", None),
    (429, json.dumps({"code": 20429, "message": "private limit details"}), 20429),
    (400, json.dumps({"code": "private\nforged log entry"}), None),
    (400, json.dumps(["private unexpected response"]), None),
])
def test_inbox_page_errors_keep_status_and_code_without_private_details(
    monkeypatch, caplog, later_page, status, body, code,
):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    for name, value in {
        "TWILIO_ACCOUNT_SID": "AC-private", "TWILIO_AUTH_TOKEN": "private-token",
        "TWILIO_PHONE_NUMBER": "+15551234567", "YOUR_PHONE_NUMBER": "+15557654321",
    }.items():
        monkeypatch.setenv(name, value)
    caplog.set_level(logging.INFO)
    caplog.set_level(logging.INFO, logger="twilio.http_client")

    failure = Response()
    failure.status_code = status
    failure._content = body.encode()
    responses = [failure]
    if later_page:
        first_page = Response()
        first_page.status_code = 200
        first_page._content = json.dumps({
            "messages": [],
            "next_page_uri": "/2010-04-01/Accounts/AC-private/Messages.json?Page=1",
        }).encode()
        responses.insert(0, first_page)
    pages = iter(responses)
    requests_made = []

    def send(session, request, **kwargs):
        requests_made.append(request)
        return next(pages)

    monkeypatch.setattr("requests.Session.send", send)
    response = create_app().test_client().post(
        "/sms/inbox", json={"after": "2026-09-05T00:00:00Z"},
    )

    assert len(requests_made) == (2 if later_page else 1)
    assert response.status_code == 502
    assert response.json == {"error": "SMS provider unavailable"}
    assert "TwilioException" in caplog.text
    assert f"status={status} code={code}" in caplog.text
    assert "reason=Unable to fetch page" in caplog.text
    assert "operation=inbox" in caplog.text
    for private in (
        "private", "+15551234567", "+15557654321", "%2B15551234567", "%2B15557654321",
    ):
        assert private not in caplog.text


def test_inbox_keeps_fixed_sdk_deserialization_reason(monkeypatch, caplog):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    for name, value in {
        "TWILIO_ACCOUNT_SID": "AC-test", "TWILIO_AUTH_TOKEN": "private-token",
        "TWILIO_PHONE_NUMBER": "+15551234567", "YOUR_PHONE_NUMBER": "+15557654321",
    }.items():
        monkeypatch.setenv(name, value)
    malformed_page = Response()
    malformed_page.status_code = 200
    malformed_page._content = b'{"unexpected": "private", "another": "private"}'
    monkeypatch.setattr("requests.Session.send", lambda *args, **kwargs: malformed_page)

    response = create_app().test_client().post(
        "/sms/inbox", json={"after": "2026-09-05T00:00:00Z"},
    )

    assert response.status_code == 502
    assert "reason=Page Records can not be deserialized" in caplog.text
    assert "private" not in caplog.text
