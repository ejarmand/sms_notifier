# SMS Notifier

A private HTTP service for life_tracker to send SMS through Twilio and read
replies. Access is controlled by Tailscale network policy. There are no
application keys, auth endpoints, challenge database, or public HTTP listener.

## API

| Request | Result |
| --- | --- |
| `GET /health` | `{"status": "healthy"}`; does not contact Twilio |
| `POST /sms/send` with `{"message": "Check in"}` | `{"status": "success", "message_id": "SM..."}` |
| `POST /sms/inbox` with `{"after": "2026-09-05T12:00:00Z"}` | `[{"sid": "SM...", "date_sent": "...", "from": "+1...", "body": "..."}]` |

Send always targets `YOUR_PHONE_NUMBER` from `TWILIO_PHONE_NUMBER`. Messages
must contain 1–1600 characters and cannot be whitespace-only. Inbox returns
inbound messages from `YOUR_PHONE_NUMBER` to `TWILIO_PHONE_NUMBER`. Its cursor
must include a timezone; it is normalized to UTC before querying Twilio.
Twilio's SDK list call follows pagination. The server keeps no message state.

Unknown request fields, including old auth fields and recipient overrides,
return 400. Provider HTTP or connection failures return 502. Do not blindly
retry an unsuccessful send: a timeout can occur after Twilio accepted it.

## Client

```python
from datetime import datetime, timedelta, timezone
from sms_client import SMSClient

with SMSClient("http://100.64.10.20:5000") as client:
    client.send("What are you working on?")
    replies = client.inbox(datetime.now(timezone.utc) - timedelta(minutes=15))
```

The client requires Python 3.12 or newer and requests. It connects directly,
ignoring HTTP proxy environment variables. Inbox accepts an aware `datetime`
and deduplicates SIDs for the life of the client instance. The caller must
persist its cursor and recent SIDs across restarts and use an overlapping
polling window. The server does not associate replies with particular prompts.

## Deploy on Debian 11

Use the [life_tracker deployment guide](https://github.com/ejarmand/life_tracker/blob/main/docs/sms-deployment.md)
for the setup helper, Tailscale policy, and send/reply checks.

Before starting the service:

1. Join the node to your tailnet. Grant TCP port 5000 only to intended callers;
   remove any broader allow rules that would also grant access. Any process on
   an allowed device can call this API. Do not publicly proxy the HTTP port.
2. Install standalone uv in a system path. The installer uses uv-managed
   Python 3.12 under `/opt/sms-notifier/python`, leaving system Python alone.
3. Put `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`, and
   `YOUR_PHONE_NUMBER` in separate root-owned 0600 files under
   `/etc/sms-notifier/credentials`, a root-owned 0700 directory.
4. Set `SMSN_BIND=100.x.y.z:5000` in `/etc/sms-notifier/server.conf`, using the
   node's actual Tailscale IPv4 address. The default is loopback. Gunicorn
   rejects wildcard and public bind addresses.
5. Run `sudo ./deploy/install.sh`. It installs and restarts a single sync
   gunicorn worker under systemd, with `LoadCredential=` for secrets. Logs go
   to the journal. The service needs no writable state directory.

## Migration from 0.2

Version 0.3 removes RSA authentication. Old clients are incompatible with the
new service. The code in `client_legacy/` remains available for the old server;
keep that deployment running for HPC callers during migration.

External access will be handled separately in [issue #3](https://github.com/ejarmand/sms_notifier/issues/3).
Old `/etc/sms-notifier/authorized_keys` and `/var/lib/sms-notifier/challenges.db`
are no longer used. Installation leaves those files in place for rollback.

## Development

```bash
uv sync
uv run pytest
```

Tests exercise real client-to-server HTTP with Twilio mocked, request validation,
provider failures, credential loading, and deployment bind restrictions. They do
not send real SMS. There is no fake-success mode in the deployed service.

## License

MIT
