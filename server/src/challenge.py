import base64
import os
import secrets
import sqlite3
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


DATABASE_PATH = os.environ.get(
    "SMSN_DATABASE_PATH", "/var/lib/sms-notifier/challenges.db"
)
AUTHORIZED_KEYS_PATH = os.environ.get(
    "SMSN_AUTHORIZED_KEYS_PATH", "/etc/sms-notifier/authorized_keys"
)
CHALLENGE_TTL_SECONDS = int(os.environ.get("SMSN_CHALLENGE_TTL_SECONDS", "60"))


def init_db():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                challenge TEXT NOT NULL,
                expire_time TEXT NOT NULL
            )"""
        )


def issue_challenge(hostname):
    challenge = secrets.token_hex(32)
    expires_at = datetime.now() + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO challenges
               (hostname, challenge, expire_time) VALUES (?, ?, ?)""",
            (hostname, challenge, expires_at.isoformat()),
        )
    return challenge


def load_authorized_keys():
    """Map OpenSSH RSA key comments to public keys."""
    if not os.path.exists(AUTHORIZED_KEYS_PATH):
        return {}

    keys = {}
    with open(AUTHORIZED_KEYS_PATH, encoding="utf-8") as key_file:
        for line_number, raw_line in enumerate(key_file, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            try:
                key_type_index = parts.index("ssh-rsa")
                key_data = parts[key_type_index + 1]
            except (ValueError, IndexError):
                continue

            comment_parts = parts[key_type_index + 2 :]
            hostname = " ".join(comment_parts) or f"key_{line_number}"
            try:
                public_key = serialization.load_ssh_public_key(
                    f"ssh-rsa {key_data}".encode()
                )
            except (TypeError, ValueError):
                continue
            keys[hostname] = public_key
    return keys


def verify_challenge_response(hostname, challenge, signature, public_key=None):
    """Verify that a hostname's public key signed a challenge value."""
    if public_key is None:
        public_key = load_authorized_keys().get(hostname)
    if public_key is None:
        return False

    try:
        signature_bytes = base64.b64decode(signature, validate=True)
        public_key.verify(
            signature_bytes,
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def get_challenge_for_hostname(hostname):
    with sqlite3.connect(DATABASE_PATH) as connection:
        result = connection.execute(
            "SELECT challenge, expire_time FROM challenges WHERE hostname = ?",
            (hostname,),
        ).fetchone()

    if result is None:
        return None
    challenge, expires_at = result
    if datetime.now() > datetime.fromisoformat(expires_at):
        return None
    return challenge


def clean_expired_challenges():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            "DELETE FROM challenges WHERE expire_time < ?",
            (datetime.now().isoformat(),),
        )
