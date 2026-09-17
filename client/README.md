# SMS Notifier client

Direct HTTP client for the tailnet-only SMS service, Python 3.12 or newer.
Tailscale policy controls access; no application keys or SSH tunnels are needed.

```python
from datetime import datetime, timedelta, timezone
from sms_client import SMSClient

with SMSClient("http://100.64.10.20:5000") as client:
    client.send("Check in")
    replies = client.inbox(datetime.now(timezone.utc) - timedelta(minutes=15))
```

`ring()` submits one phone ring alarm through `POST /voice/ring` with `{}` and
returns `status` and `call_id`. The server uses its SMS credentials and numbers.
It accepts no call options. Requires a server revision with the voice endpoint;
older servers return 404. Ring requests never follow redirects or retry.

`send(message)` returns a dictionary with `status` and `message_id`.
`inbox(after)` takes an aware
`datetime` and returns `sid`, `date_sent`, `from`, and `body` for personal replies.
HTTP errors raise `requests.HTTPError`; requests time out after 30 seconds by
default. Pass `timeout=` to change that. HTTP proxy environment variables are
ignored so requests go directly to the private endpoint.

SIDs are deduplicated in memory per client instance. The caller owns durable
cursor/SID storage and should poll with an overlapping time window. Avoid
blindly retrying sends after timeouts because delivery may already have started.

Install from a checkout with `uv add ./client`, or from a pinned commit:

```bash
uv add 'sms-notifier-client @ git+https://github.com/ejarmand/sms_notifier.git@COMMIT#subdirectory=client'
```

Version 0.3 requires the service without RSA auth. The old HPC CLI in
`client_legacy/` still targets the previous deployment. External access to this
service is tracked in [issue #3](https://github.com/ejarmand/sms_notifier/issues/3).
