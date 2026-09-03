import base64
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class SMSClient:
    """Authenticated direct HTTP client for SMS Notifier."""

    def __init__(
        self,
        server_url: str,
        hostname: str,
        private_key_path: str | Path,
        *,
        timeout: float = 30,
        session: requests.Session | None = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.hostname = hostname
        self.timeout = timeout
        self._session = session or requests.Session()
        self._owns_session = session is None
        self._seen_sids: set[str] = set()
        with Path(private_key_path).expanduser().open("rb") as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

    def close(self) -> None:
        if self._owns_session:
            self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def send(self, message: str) -> dict[str, Any]:
        """Send one SMS to the server's configured recipient."""
        return self._post_authenticated("/sms/send", {"message": message})

    def inbox(self, after: str | datetime) -> list[dict[str, Any]]:
        """Return messages after a timestamp that this instance has not seen."""
        if isinstance(after, datetime):
            if after.tzinfo is None:
                raise ValueError("after must include a timezone")
            after = after.isoformat()

        messages = self._post_authenticated("/sms/inbox", {"after": after})
        unseen = []
        for message in messages:
            sid = message["sid"]
            if sid not in self._seen_sids:
                unseen.append(message)
                self._seen_sids.add(sid)
        return unseen

    def _post_authenticated(
        self, endpoint: str, fields: dict[str, Any]
    ) -> Any:
        challenge_response = self._session.post(
            f"{self.server_url}/auth/challenge",
            json={"hostname": self.hostname},
            timeout=self.timeout,
        )
        challenge_response.raise_for_status()
        challenge = challenge_response.json()["challenge"]

        signature = self._private_key.sign(
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        payload = {
            "hostname": self.hostname,
            "challenge": challenge,
            "signature": base64.b64encode(signature).decode("ascii"),
            **fields,
        }
        response = self._session.post(
            f"{self.server_url}{endpoint}",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
