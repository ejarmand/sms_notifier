import os
from ipaddress import IPv4Address, IPv4Network


bind = os.environ.get("SMSN_BIND", "127.0.0.1:5000")
host, port = bind.rsplit(":", 1)
address = IPv4Address(host)
if not (address.is_loopback or address in IPv4Network("100.64.0.0/10")) or not 1 <= int(port) <= 65535:
    raise ValueError("SMSN_BIND must use a loopback or Tailscale IPv4 address and a valid port")
workers = 1
worker_class = "sync"
timeout = 30
graceful_timeout = 30
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
