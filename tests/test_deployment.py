import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "server"))

from src.config import get_secret  # noqa: E402


def test_gunicorn_uses_configured_bind_and_one_sync_worker(monkeypatch):
    monkeypatch.setenv("SMSN_BIND", "100.64.10.20:8080")

    config = runpy.run_path(str(ROOT / "server" / "gunicorn.conf.py"))

    assert config["bind"] == "100.64.10.20:8080"
    assert config["workers"] == 1
    assert config["worker_class"] == "sync"


def test_systemd_unit_loads_all_twilio_values_as_credentials():
    unit = (ROOT / "deploy" / "sms-notifier.service").read_text()

    for name in (
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_PHONE_NUMBER",
        "YOUR_PHONE_NUMBER",
    ):
        assert f"LoadCredential={name}:/etc/sms-notifier/credentials/{name}" in unit
    assert "EnvironmentFile=-/etc/sms-notifier/server.conf" in unit


def test_install_uses_uv_managed_python_312():
    script = (ROOT / "deploy" / "install.sh").read_text()

    assert (ROOT / ".python-version").read_text().strip() == "3.12"
    assert "uv python install 3.12" in script
    assert "uv sync --frozen --no-dev" in script
    assert "apt install python" not in script
    assert "pip install" not in script


def test_secret_can_come_from_systemd_credentials(tmp_path, monkeypatch):
    credential = tmp_path / "TWILIO_AUTH_TOKEN"
    credential.write_text("token-from-systemd\n")
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

    assert get_secret("TWILIO_AUTH_TOKEN") == "token-from-systemd"


def test_systemd_credential_takes_precedence_over_environment(
    tmp_path, monkeypatch
):
    credential = tmp_path / "TWILIO_AUTH_TOKEN"
    credential.write_text("token-from-systemd\n")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token-from-environment")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

    assert get_secret("TWILIO_AUTH_TOKEN") == "token-from-systemd"
