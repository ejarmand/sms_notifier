import sqlite3
from datetime import datetime, timedelta
import secrets
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Configurable paths via environment variables
DATABASE_PATH = os.environ.get("SMSN_DATABASE_PATH", "/app/data/auth_challenge.db")
AUTHORIZED_KEYS_PATH = os.environ.get("SMSN_AUTHORIZED_KEYS_PATH", "/app/auth/authorized_keys")
CHALLENGE_TTL_SECONDS = int(os.environ.get("SMSN_CHALLENGE_TTL_SECONDS", "60"))

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Enable Write-Ahead Logging for better concurrency
    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute('''CREATE TABLE IF NOT EXISTS challenges
                 (id INTEGER PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE,
                    challenge TEXT NOT NULL,
                    expire_time TEXT NOT NULL)''')
    conn.commit()

def issue_challenge(hostname):
    # generates a challenge for a given host and adds it
    # to the challenge db
    challenge = secrets.token_hex(32)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    expiretime = datetime.now() + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    cursor.execute('INSERT OR REPLACE INTO challenges (hostname, challenge, expire_time) VALUES (?, ?, ?)',
                   (hostname, challenge, expiretime.isoformat()))
    conn.commit()
    conn.close()
    return challenge

def load_authorized_keys():
    """Load and parse authorized public keys from the authorized_keys file.

    Supports standard OpenSSH authorized_keys format. The trailing comment is
    used as the hostname/client identifier.
    """
    if not os.path.exists(AUTHORIZED_KEYS_PATH):
        return {}

    keys = {}
    with open(AUTHORIZED_KEYS_PATH, 'r', encoding='utf-8') as f:
        for line_num, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue

            try:
                parts = line.split()
                # Options may precede the key type; find the ssh-rsa token
                try:
                    idx = parts.index('ssh-rsa')
                except ValueError:
                    # Unsupported or malformed line
                    continue

                if len(parts) <= idx + 1:
                    continue

                key_type = parts[idx]
                key_data = parts[idx + 1]
                comment = ' '.join(parts[idx + 2:]) if len(parts) > idx + 2 else f"key_{line_num}"

                if key_type == 'ssh-rsa':
                    # cryptography expects the full OpenSSH-formatted key string
                    public_key = serialization.load_ssh_public_key(
                            f"{key_type} {key_data}".encode('utf-8'))
                    keys[comment] = public_key

            except Exception as e:
                print(f"Warning: Failed to parse key on line {line_num}: {e}")
                continue

    return keys

def verify_challenge_response(hostname, challenge, signature, public_key=None):
    """Verify that the challenge response was signed by the 
    authorized key for the hostname.
    
    Args:
        hostname: The hostname/client identifier
        challenge: The challenge string that was signed
        signature: Base64-encoded signature
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Decode the base64 signature
        signature_bytes = base64.b64decode(signature)
        
        # Verify the signature
        public_key.verify(
            signature_bytes,
            challenge.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False

def get_challenge_for_hostname(hostname):
    """Retrieve the current challenge for a hostname from the database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
            'SELECT challenge, expire_time FROM challenges WHERE hostname = ?',
            (hostname,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None
    
    challenge, expire_time_str = result
    expire_time = datetime.fromisoformat(expire_time_str)
    
    if datetime.now() > expire_time:
        # Challenge has expired
        return None
    
    return challenge

def clean_expired_challenges():
    """Remove expired challenges from the database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    current_time = datetime.now().isoformat()
    cursor.execute('DELETE FROM challenges WHERE expire_time < ?', 
                   (current_time,))
    
    conn.commit()
    conn.close()
