import os


bind = os.environ.get("SMSN_BIND", "127.0.0.1:5000")
workers = 1
worker_class = "sync"
timeout = 30
graceful_timeout = 30
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
