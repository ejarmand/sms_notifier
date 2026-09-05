from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
import json

import pytest
from requests import ConnectionError
from twilio.base.exceptions import TwilioRestException


@pytest.fixture
def service(monkeypatch, tmp_path):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC-test")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "test-token")
    monkeypatch.setenv("TWILIO_PHONE_NUMBER", "+15551234567")
    monkeypatch.setenv("YOUR_PHONE_NUMBER", "+15557654321")
    # The simplified service must start without a writable auth database.
    monkeypatch.setenv("SMSN_DATABASE_PATH", str(tmp_path / "absent" / "auth.db"))
    import sms_notifier

    provider = Mock()
    provider.messages.create.return_value.sid = "SM-sent"
    monkeypatch.setattr(sms_notifier, "Client", Mock(return_value=provider))
    app = sms_notifier.create_app()
    app.testing = True
    return app, provider


def test_send_without_application_credentials(service):
    app, provider = service
    response = app.test_client().post("/sms/send", json={"message": "Check in"})

    assert response.status_code == 200
    assert response.json["message_id"] == "SM-sent"
    provider.messages.create.assert_called_once_with(
        body="Check in", from_="+15551234567", to="+15557654321"
    )


def test_inbox_reads_only_personal_replies_with_a_utc_cursor(service):
    app, provider = service
    when = datetime(2026, 9, 5, 19, 1, tzinfo=timezone.utc)
    provider.messages.list.return_value = [
        SimpleNamespace(sid="SM-reply", date_sent=when, direction="inbound",
                        from_="+15557654321", to="+15551234567", body="Working on life_tracker"),
        SimpleNamespace(sid="SM-other", date_sent=when, direction="inbound",
                        from_="+15559999999", to="+15551234567", body="Other sender"),
        SimpleNamespace(sid="SM-out", date_sent=when, direction="outbound-api",
                        from_="+15551234567", to="+15557654321", body="Check in"),
    ]

    response = app.test_client().post("/sms/inbox", json={"after": "2026-09-05T12:00:00-07:00"})

    assert response.status_code == 200
    assert response.json == [{"sid": "SM-reply", "date_sent": "2026-09-05T19:01:00+00:00",
                              "from": "+15557654321", "body": "Working on life_tracker"}]
    provider.messages.list.assert_called_once_with(
        date_sent_after=datetime(2026, 9, 5, 19, 0, tzinfo=timezone.utc),
        from_="+15557654321", to="+15551234567",
    )
    assert provider.messages.list.call_args.kwargs["date_sent_after"].tzinfo is timezone.utc


@pytest.mark.parametrize("path,payload", [
    ("/sms/send", None), ("/sms/send", ["message"]),
    ("/sms/send", {"message": ""}), ("/sms/send", {"message": 42}),
    ("/sms/send", {"message": "x" * 1601}),
    ("/sms/send", {"message": "Hi", "to": "+15550000000"}),
    ("/sms/send", {"message": "Hi", "hostname": "old-client"}),
    ("/sms/inbox", {}), ("/sms/inbox", {"after": "2026-09-05T12:00:00"}),
    ("/sms/inbox", {"after": "yesterday"}), ("/sms/inbox", {"after": 123}),
])
def test_invalid_requests_do_not_reach_twilio(service, path, payload):
    app, provider = service
    response = app.test_client().post(path, data=json.dumps(payload), content_type="application/json")
    assert response.status_code == 400
    assert "error" in response.json
    provider.messages.create.assert_not_called()
    provider.messages.list.assert_not_called()


@pytest.mark.parametrize("failure", [
    TwilioRestException(503, "https://api.twilio.com", msg="private provider details"),
    ConnectionError("private transport details"),
])
@pytest.mark.parametrize("path,payload,operation", [
    ("/sms/send", {"message": "Check in"}, "create"),
    ("/sms/inbox", {"after": "2026-09-05T12:00:00Z"}, "list"),
])
def test_provider_failure_is_a_502_without_sensitive_details(service, failure, path, payload, operation, caplog):
    app, provider = service
    getattr(provider.messages, operation).side_effect = failure
    response = app.test_client().post(path, json=payload)
    assert response.status_code == 502
    assert response.json == {"error": "SMS provider unavailable"}
    assert "private" not in caplog.text


def test_health_and_removed_auth_routes(service):
    app, _ = service
    client = app.test_client()
    assert client.get("/health").json == {"status": "healthy"}
    assert client.post("/auth/challenge", json={"hostname": "old"}).status_code == 404
    assert client.post("/auth/verify", json={}).status_code == 404


@pytest.mark.parametrize("name", ["TWILIO_PHONE_NUMBER", "YOUR_PHONE_NUMBER"])
@pytest.mark.parametrize("value", [
    "15557654321", "+1 555 765 4321", "+15557654321 ",
    "+05557654321", "+1234567890123456", "+1５５５７６５４３２１",
])
def test_startup_rejects_noncanonical_phone_credentials(service, monkeypatch, name, value):
    from sms_notifier import create_app

    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=f"{name} must use E.164 format") as error:
        create_app()
    assert value not in str(error.value)
