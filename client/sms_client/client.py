from datetime import datetime
from typing import Any

import requests


class SMSClient:
    """Direct client for the private tailnet SMS service."""

    def __init__(self, server_url: str, *, timeout: float = 30):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.trust_env = False
        self._seen_sids: set[str] = set()

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def send(self, message: str) -> dict[str, Any]:
        """Send one SMS to the server's configured recipient."""
        response = self._session.post(
            f"{self.server_url}/sms/send", json={"message": message}, timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()

    def inbox(self, after: datetime) -> list[dict[str, Any]]:
        """Read replies after an aware timestamp, deduplicating SIDs in memory."""
        if after.tzinfo is None or after.utcoffset() is None:
            raise ValueError("after must include a timezone")
        response = self._session.post(
            f"{self.server_url}/sms/inbox",
            json={"after": after.isoformat()}, timeout=self.timeout,
        )
        response.raise_for_status()
        unseen = []
        for message in response.json():
            if message["sid"] not in self._seen_sids:
                unseen.append(message)
                self._seen_sids.add(message["sid"])
        return unseen
