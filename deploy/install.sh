#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    echo "Install the standalone uv binary before running this script." >&2
    exit 1
fi

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL_DIR=/opt/sms-notifier
CONFIG_DIR=/etc/sms-notifier
CREDENTIAL_DIR=$CONFIG_DIR/credentials

if ! getent group sms-notifier >/dev/null; then
    groupadd --system sms-notifier
fi
if ! id -u sms-notifier >/dev/null 2>&1; then
    useradd --system --gid sms-notifier --home-dir /nonexistent \
        --shell /usr/sbin/nologin sms-notifier
fi

install -d -m 0755 "$INSTALL_DIR" "$INSTALL_DIR/server" \
    "$INSTALL_DIR/server/src" \
    "$INSTALL_DIR/client" "$INSTALL_DIR/client/sms_client"
# Remove retired modules before packaging an upgrade over the 0.2 checkout.
rm -f "$INSTALL_DIR/server/src/challenge.py" "$INSTALL_DIR/server/src/logging_config.py" \
    "$INSTALL_DIR/server/blueprints/auth.py" "$INSTALL_DIR/server/blueprints/sms.py" \
    "$INSTALL_DIR/server/blueprints/__init__.py"
install -m 0644 "$SOURCE_DIR/pyproject.toml" "$SOURCE_DIR/uv.lock" \
    "$SOURCE_DIR/.python-version" "$INSTALL_DIR/"
install -m 0644 "$SOURCE_DIR/server/pyproject.toml" \
    "$SOURCE_DIR/server/sms_notifier.py" \
    "$SOURCE_DIR/server/gunicorn.conf.py" "$INSTALL_DIR/server/"
install -m 0644 "$SOURCE_DIR"/server/src/*.py "$INSTALL_DIR/server/src/"
install -m 0644 "$SOURCE_DIR/client/pyproject.toml" \
    "$SOURCE_DIR/client/README.md" "$INSTALL_DIR/client/"
install -m 0644 "$SOURCE_DIR"/client/sms_client/*.py \
    "$INSTALL_DIR/client/sms_client/"

export UV_PYTHON_INSTALL_DIR=$INSTALL_DIR/python
cd "$INSTALL_DIR"
uv python install 3.12
uv sync --frozen --no-dev --package sms-notifier-server \
    --reinstall-package sms-notifier-server --python 3.12

install -d -m 0755 "$CONFIG_DIR"
install -d -m 0700 "$CREDENTIAL_DIR"
if [ ! -e "$CONFIG_DIR/server.conf" ]; then
    install -m 0644 "$SOURCE_DIR/deploy/server.conf" "$CONFIG_DIR/server.conf"
fi

for name in TWILIO_ACCOUNT_SID TWILIO_AUTH_TOKEN TWILIO_PHONE_NUMBER YOUR_PHONE_NUMBER; do
    if [ ! -f "$CREDENTIAL_DIR/$name" ]; then
        echo "Missing $CREDENTIAL_DIR/$name" >&2
        exit 1
    fi
    chmod 0600 "$CREDENTIAL_DIR/$name"
    chown root:root "$CREDENTIAL_DIR/$name"
done

install -m 0644 "$SOURCE_DIR/deploy/sms-notifier.service" \
    /etc/systemd/system/sms-notifier.service
systemctl daemon-reload
systemctl enable --now sms-notifier.service
systemctl restart sms-notifier.service
