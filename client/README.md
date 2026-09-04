# SMS Notifier client

The client connects directly to an SMS Notifier server. It does not create SSH
tunnels or configure proxies.

```python
from datetime import datetime, timezone
from sms_client import SMSClient

client = SMSClient(
    "http://sms-host.tailnet:5000",
    hostname="life-tracker",
    private_key_path="~/.config/sms_notifier/id_rsa",
)

client.send("training complete")
messages = client.inbox(datetime.now(timezone.utc))
```

Each request obtains and signs a fresh RSA challenge. `inbox(after)` accepts an
ISO-8601 string or a timezone-aware `datetime`. An `SMSClient` instance returns
each Twilio SID only once. Create a new instance to reset its in-memory SID set.

Install the package with uv:

```bash
uv add 'sms-notifier-client @ git+https://github.com/ejarmand/sms_notifier.git#subdirectory=client'
```

The pre-tailnet client remains in `client_legacy/` for HPC installations that
still need SSH tunneling.
