import os
from pathlib import Path


def get_secret(name: str) -> str | None:
    """Read a setting from the environment or a systemd credential file."""
    value = os.environ.get(name)
    if value is not None:
        return value

    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_directory is None:
        return None

    credential_path = Path(credentials_directory) / name
    try:
        return credential_path.read_text(encoding="utf-8").rstrip("\r\n")
    except FileNotFoundError:
        return None
