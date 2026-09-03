import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


CLIENT_DIR = Path(__file__).parents[1] / "client"
sys.path.insert(0, str(CLIENT_DIR))

from sms_client import SMSClient  # noqa: E402


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, inbox_responses=None):
        self.calls = []
        self.inbox_responses = iter(inbox_responses or [])

    def post(self, url, json, timeout):
        self.calls.append((url, json, timeout))
        if url.endswith("/auth/challenge"):
            return FakeResponse({"challenge": "signed-challenge"})
        if url.endswith("/sms/inbox"):
            return FakeResponse(next(self.inbox_responses))
        if url.endswith("/sms/send"):
            return FakeResponse({"message_id": "SM-sent", "status": "success"})
        raise AssertionError(f"unexpected URL: {url}")


def write_private_key(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_path = tmp_path / "id_rsa"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return private_key, private_key_path


def test_inbox_authenticates_and_deduplicates_sids_across_calls(tmp_path):
    private_key, private_key_path = write_private_key(tmp_path)
    duplicate = {
        "sid": "SM-1",
        "date_sent": "2026-09-03T12:01:00+00:00",
        "from": "+15557654321",
        "body": "breakfast",
    }
    new_message = {
        "sid": "SM-2",
        "date_sent": "2026-09-03T12:02:00+00:00",
        "from": "+15557654321",
        "body": "coffee",
    }
    session = FakeSession([[duplicate], [duplicate, new_message]])
    client = SMSClient(
        "http://sms.internal:5000/",
        "life-tracker",
        private_key_path,
        session=session,
    )

    first = client.inbox(datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc))
    second = client.inbox("2026-09-03T12:00:00Z")

    assert first == [duplicate]
    assert second == [new_message]
    inbox_payload = session.calls[1][1]
    assert inbox_payload["after"] == "2026-09-03T12:00:00+00:00"
    assert inbox_payload["hostname"] == "life-tracker"
    private_key.public_key().verify(
        base64.b64decode(inbox_payload["signature"]),
        inbox_payload["challenge"].encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def test_send_authenticates_message(tmp_path):
    _, private_key_path = write_private_key(tmp_path)
    session = FakeSession()
    client = SMSClient(
        "http://sms.internal:5000",
        "job-host",
        private_key_path,
        session=session,
    )

    result = client.send("training complete")

    assert result == {"message_id": "SM-sent", "status": "success"}
    assert session.calls[1][0] == "http://sms.internal:5000/sms/send"
    assert session.calls[1][1]["message"] == "training complete"
