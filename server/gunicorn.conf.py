"""
Gunicorn configuration for SMS Notifier Server

This configuration is optimized for production use with proper
worker management, logging, and security settings.
"""

import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', 5000)}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 100

# Preload application for better performance
preload_app = True

# Logging
accesslog = os.environ.get('GUNICORN_ACCESS_LOG', '/app/logs/gunicorn_access.log')
errorlog = os.environ.get('GUNICORN_ERROR_LOG', '/app/logs/gunicorn_error.log')
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'sms-notifier'

# Server mechanics
daemon = False
pidfile = '/tmp/gunicorn.pid'
user = 'smsuser'
group = 'smsuser'
tmp_upload_dir = None

# SSL (if needed)
# keyfile = '/app/ssl/key.pem'
# certfile = '/app/ssl/cert.pem'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance tuning
worker_tmp_dir = '/dev/shm'  # Use shared memory for worker temp files

# Graceful timeout for worker shutdown
graceful_timeout = 30

# Environment variables to pass to workers
raw_env = [
    f'LOG_LEVEL={os.environ.get("LOG_LEVEL", "INFO")}',
    f'LOG_FILE={os.environ.get("LOG_FILE", "/app/logs/sms_notifier.log")}',
]
