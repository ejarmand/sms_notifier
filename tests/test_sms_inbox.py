import base64
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


SERVER_DIR = Path(__file__).parents[1] / "server"
sys.path.insert(0, str(SERVER_DIR))

from blueprints import auth as auth_blueprint  # noqa: E402
from blueprints import sms as sms_blueprint  # noqa: E402
from sms_notifier import create_app  # noqa: E402
from src import challenge  # noqa: E402


class RecordingMessages:
    def __init__(self, messages):
        self.messages = messages
        self.filters = None

    def list(self, **filters):
        self.filters = filters
        return self.messages


class RecordingSends:
    def __init__(self):
        self.message = None

    def create(self, **message):
        self.message = message
        return SimpleNamespace(sid="SM-explicit-recipient")


def create_authenticated_app(tmp_path, monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_bytes(public_key + b" test-host\n")

    challenge.DATABASE_PATH = str(tmp_path / "challenges.db")
    challenge.AUTHORIZED_KEYS_PATH = str(authorized_keys)
    auth_blueprint._local = threading.local()
    auth_blueprint._last_mtime = None
    sms_blueprint._local = threading.local()
    if hasattr(auth_blueprint.initialize_auth, "_initialized"):
        del auth_blueprint.initialize_auth._initialized

    monkeypatch.setenv("TWILIO_PHONE_NUMBER", "+15551234567")
    app = create_app()
    app.config.update(TESTING=True)
    return app, private_key


def authenticated_payload(client, private_key, **fields):
    challenge_response = client.post(
        "/auth/challenge", json={"hostname": "test-host"}
    )
    issued_challenge = challenge_response.get_json()["challenge"]
    signature = private_key.sign(
        issued_challenge.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return {
        "hostname": "test-host",
        "challenge": issued_challenge,
        "signature": base64.b64encode(signature).decode(),
        **fields,
    }


def test_inbox_queries_twilio_after_timestamp_and_returns_only_inbound_messages(
    tmp_path, monkeypatch
):
    app, private_key = create_authenticated_app(tmp_path, monkeypatch)
    messages = RecordingMessages(
        [
            SimpleNamespace(
                sid="SM-inbound",
                date_sent=datetime(2026, 9, 3, 12, 5, tzinfo=timezone.utc),
                from_="+15557654321",
                to="+15551234567",
                body="log breakfast",
                direction="inbound",
            ),
            SimpleNamespace(
                sid="SM-outbound",
                date_sent=datetime(2026, 9, 3, 12, 6, tzinfo=timezone.utc),
                from_="+15551234567",
                to="+15557654321",
                body="ignored",
                direction="outbound-api",
            ),
        ]
    )
    monkeypatch.setattr(
        sms_blueprint,
        "get_twilio_client",
        lambda: SimpleNamespace(messages=messages),
    )

    with app.test_client() as client:
        response = client.post(
            "/sms/inbox",
            json=authenticated_payload(
                client, private_key, after="2026-09-03T12:00:00Z"
            ),
        )

    assert response.status_code == 200
    assert response.get_json() == [
        {
            "sid": "SM-inbound",
            "date_sent": "2026-09-03T12:05:00+00:00",
            "from": "+15557654321",
            "body": "log breakfast",
        }
    ]
    assert messages.filters == {
        "date_sent_after": datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
        "to": "+15551234567",
    }


def test_inbox_rejects_an_after_timestamp_without_timezone(tmp_path, monkeypatch):
    app, private_key = create_authenticated_app(tmp_path, monkeypatch)

    with app.test_client() as client:
        response = client.post(
            "/sms/inbox",
            json=authenticated_payload(
                client, private_key, after="2026-09-03T12:00:00"
            ),
        )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "after must be an ISO-8601 timestamp with a timezone"
    }


def test_send_retains_explicit_recipient_override(tmp_path, monkeypatch):
    app, private_key = create_authenticated_app(tmp_path, monkeypatch)
    monkeypatch.setenv("YOUR_PHONE_NUMBER", "+15550000000")
    messages = RecordingSends()
    monkeypatch.setattr(
        sms_blueprint,
        "get_twilio_client",
        lambda: SimpleNamespace(messages=messages),
    )

    with app.test_client() as client:
        response = client.post(
            "/sms/send",
            json=authenticated_payload(
                client,
                private_key,
                message="legacy request",
                to="+15559999999",
            ),
        )

    assert response.status_code == 200
    assert messages.message == {
        "body": "legacy request",
        "from_": "+15551234567",
        "to": "+15559999999",
    }
    assert response.get_json()["to"] == "+15559999999"
