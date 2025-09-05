import os
import sys
import base64
import importlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def load_challenge_module(tmp_path: Path, authorized_keys_contents: str, ttl_seconds: int = 60):
    # Write authorized_keys file
    auth_path = tmp_path / "authorized_keys"
    auth_path.write_text(authorized_keys_contents, encoding="utf-8")

    # Database path
    db_path = tmp_path / "auth_challenge.db"

    # Ensure challenge module can be imported from server/src
    src_dir = Path("server") / "src"
    assert src_dir.exists(), "Expected server/src directory to exist"
    sys.path.insert(0, str(src_dir))

    # Configure env BEFORE import
    os.environ["SMSN_AUTHORIZED_KEYS_PATH"] = str(auth_path)
    os.environ["SMSN_DATABASE_PATH"] = str(db_path)
    os.environ["SMSN_CHALLENGE_TTL_SECONDS"] = str(ttl_seconds)

    import challenge  # type: ignore
    importlib.reload(challenge)
    return challenge


def generate_keypair(bits: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_ssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return private_key, public_ssh


def test_signature_verification_with_authorized_key(tmp_path: Path):
    private_key, public_ssh = generate_keypair()
    comment = "test-host"
    auth_line = public_ssh.decode("utf-8") + f" {comment}\n"

    challenge = load_challenge_module(tmp_path, auth_line)
    challenge.init_db()

    issued = challenge.issue_challenge(comment)
    # Get the current challenge from DB and sign it
    current = challenge.get_challenge_for_hostname(comment)
    assert current == issued

    signature = private_key.sign(
        current.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature).decode("ascii")

    assert challenge.verify_challenge_response(comment, current, sig_b64) is True
    # Unknown host should fail
    assert challenge.verify_challenge_response("unknown", current, sig_b64) is False

    # Wrong private key signing should fail
    wrong_priv, _ = generate_keypair()
    wrong_sig = wrong_priv.sign(
        current.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    wrong_sig_b64 = base64.b64encode(wrong_sig).decode("ascii")
    assert challenge.verify_challenge_response(comment, current, wrong_sig_b64) is False

    # Tampered challenge should fail
    tampered = current + "-tamper"
    assert challenge.verify_challenge_response(comment, tampered, sig_b64) is False

def test_expired_challenge_returns_none(tmp_path: Path):
    # TTL 0 means immediately expired
    _, public_ssh = generate_keypair()
    comment = "expiring-host"
    auth_line = public_ssh.decode("utf-8") + f" {comment}\n"

    challenge = load_challenge_module(tmp_path, auth_line, ttl_seconds=0)
    challenge.init_db()
    _ = challenge.issue_challenge(comment)

    # Should be considered expired immediately
    assert challenge.get_challenge_for_hostname(comment) is None
