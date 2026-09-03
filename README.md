# SMS Notifier

SMS Notifier is a small Flask service for sending and reading SMS through
Twilio. Clients authenticate each request by signing a short-lived RSA
challenge. The server is meant to listen on a tailnet address and does not need
nginx, Docker, or a public listener.

## API

The Flask app keeps its authentication and SMS blueprints.

- `GET /health` reports service health.
- `POST /auth/challenge` accepts `{"hostname": "client-name"}`.
- `POST /auth/verify` verifies `hostname`, `challenge`, and `signature`.
- `POST /sms/send` accepts the authentication fields, `message`, and an optional
  `to` override. Without `to`, it sends to the configured `YOUR_PHONE_NUMBER`.
- `POST /sms/inbox` accepts the authentication fields and a timezone-aware
  ISO-8601 `after` value. It queries Twilio with `date_sent_after`, limits the
  query to messages addressed to `TWILIO_PHONE_NUMBER`, drops non-inbound
  results, and returns objects with `sid`, `date_sent`, `from`, and `body`.

The inbox endpoint queries Twilio on every request. It does not store messages
or polling cursors.

## Client

The package in `client/` makes direct HTTP requests and has two public methods:

```python
from datetime import datetime, timezone
from sms_client import SMSClient

with SMSClient(
    "http://100.64.10.20:5000",
    hostname="life-tracker",
    private_key_path="/home/me/.config/sms_notifier/id_rsa",
) as client:
    client.send("training complete")
    messages = client.inbox(datetime.now(timezone.utc))
```

Each client instance suppresses Twilio SIDs it has already returned. The set is
kept in memory, so a new client instance starts with an empty set. The old CLI
and its SSH tunnel support remain in `client_legacy/` for HPC use.

Install the new package from a checkout with:

```bash
uv add ./client
```

The server identifies a client by the comment at the end of its OpenSSH public
key line. For the example above, `/etc/sms-notifier/authorized_keys` needs a line
whose comment is `life-tracker`.

## Debian 11 deployment

The supplied unit targets Debian 11 with systemd 247. Install uv as a standalone
binary first. The installer never invokes Debian's Python or pip. uv installs
Python 3.12 below `/opt/sms-notifier/python` and creates the service virtual
environment at `/opt/sms-notifier/.venv`.

Create these four root-readable files before installation:

```text
/etc/sms-notifier/credentials/TWILIO_ACCOUNT_SID
/etc/sms-notifier/credentials/TWILIO_AUTH_TOKEN
/etc/sms-notifier/credentials/TWILIO_PHONE_NUMBER
/etc/sms-notifier/credentials/YOUR_PHONE_NUMBER
```

Each file contains only its value and an optional final newline. The systemd
unit uses `LoadCredential=` for all four files. The Flask process reads the
private copies exposed through `CREDENTIALS_DIRECTORY`; the values do not
appear in the unit's environment.

Run the installer from the repository root:

```bash
sudo ./deploy/install.sh
```

The first installation creates `/etc/sms-notifier/server.conf` with a loopback
default. Change `SMSN_BIND` to the server's tailnet address, then restart the
service:

```text
SMSN_BIND=100.64.10.20:5000
LOG_LEVEL=INFO
```

```bash
sudo systemctl restart sms-notifier
sudo systemctl status sms-notifier
```

Add client public keys to `/etc/sms-notifier/authorized_keys`, one OpenSSH RSA
key per line. Gunicorn binds directly to `SMSN_BIND` and runs one sync worker.

## Development

The repository is an uv workspace pinned to Python 3.12:

```bash
uv sync
uv run pytest
```

For a local debug server, set temporary environment values and run Flask from
the server package:

```bash
SMS_DEBUG_MODE=true \
TWILIO_PHONE_NUMBER=+15551234567 \
YOUR_PHONE_NUMBER=+15557654321 \
SMSN_AUTHORIZED_KEYS_PATH=./authorized_keys \
SMSN_DATABASE_PATH=./challenges.db \
uv run --directory server flask --app sms_notifier:create_app run
```

## License

MIT
