import os
from pathlib import Path


def get_secret(name: str) -> str | None:
    """Read a systemd credential, falling back to the environment."""
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_directory is not None:
        credential_path = Path(credentials_directory) / name
        try:
            return credential_path.read_text(encoding="utf-8").rstrip("\r\n")
        except FileNotFoundError:
            pass

    return os.environ.get(name)
