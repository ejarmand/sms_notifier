# SMS Notifier Client

A command-line client for the SMS Notifier service with public key authentication.

## Installation

Install directly from GitHub:

with pip

```bash
pip install git+https://github.com/ejarmand/sms-notifier.git#subdirectory=client
```
Global cli install with uv

```bash
uv tool install 'git+https://github.com/ejarmand/sms_notifier.git#subdirectory=client'
```

Or for development:

```bash
git clone https://github.com/ejarmand/sms-notifier.git
cd sms-notifier/client
pip install -e .
```

## Quick Start

1. **Initialize the client**:
    ```bash
    sms-cli init --server-url http://external-server:5000\
        --to-number=+1012345678 # your phone number in E164 format \
        --ssh-hostname bastion # optional config for using an ssh proxy
    ```

    **note:** you will need to add your RSA public key to the server for verification 

2. **Send an SMS**:
   ```bash
   sms-cli send "Hello from the client!"
   ```

3. **Test connection**:
   ```bash
   sms-cli test
   ```

4. **Send job status updates**
    ```bash
    sms-cli stat --message-on fail bwa mem [...]
    ```

### For External Servers (SSH Proxy)

If your SMS server is external and requires SSH tunneling, you have two options:

**Option 1: Use SSH config hostname (recommended)**
```bash
sms-cli init \
  --server-url http://external-server:5000 \
  --ssh-hostname bastion
```

**Option 2: Manual SSH proxy configuration**
```bash
sms-cli init \
  --server-url http://external-server:5000 \
  --ssh-proxy-host bastion.example.com \
  --ssh-proxy-user myuser \
  --ssh-proxy-key ~/.ssh/id_rsa
```

**With verbose SSH debugging:**
```bash
sms-cli init \
  --server-url http://external-server:5000 \
  --ssh-hostname bastion \
  --ssh-verbose
```

## Configuration

The client stores configuration in `XDG_CONFIG_HOME/sms_notifier/config.json` 
and will store rsa key pairs there as well by default:

```json
{
  "server_url": "http://your-server:8080",
  "hostname": "your-hostname",
  "private_key_path": "/path/to/private/key",
  "to_number": "+1234567890"
}
```

### SSH Proxy Configuration

For external servers not on your Tailnet, you can configure SSH proxy tunneling in two ways:

**Option 1: Use SSH config hostname (recommended)**
```json
{
  "server_url": "http://external-server:5000",
  "hostname": "your-hostname",
  "private_key_path": "/path/to/private/key",
  "to_number": "+1234567890",
  "ssh_proxy": {
    "hostname": "bastion"
  }
}
```

This will automatically load all SSH settings from your `~/.ssh/config` file for the "bastion" host.

**Option 2: Manual SSH proxy configuration**
```json
{
  "server_url": "http://external-server:5000",
  "hostname": "your-hostname",
  "private_key_path": "/path/to/private/key",
  "to_number": "+1234567890",
  "ssh_proxy": {
    "host": "bastion.example.com",
    "port": 22,
    "user": "myuser",
    "key": "/path/to/ssh/private/key",
    "jump": "user@bastion:22"
  }
}
```

**SSH Proxy Options:**
- `hostname`: SSH hostname from ~/.ssh/config (loads all settings automatically)
- `host`: SSH proxy/bastion hostname (required if not using hostname)
- `port`: SSH proxy port (default: 22)
- `user`: SSH username for proxy connection
- `key`: Path to SSH private key for proxy authentication
- `jump`: ProxyJump configuration (e.g., "user@bastion:22")
- `verbose`: Enable verbose SSH debugging output (default: false)

The client will automatically create an SSH tunnel when needed and route traffic through it. The tunnel target is automatically inferred from your `server_url`.

### SSH Config Setup

To use the SSH hostname option, add an entry to your `~/.ssh/config` file:

```
Host bastion
    HostName bastion.example.com
    Port 22
    User myuser
    IdentityFile ~/.ssh/id_rsa
    ProxyJump user@jump-server:22
```

Then simply use `--ssh-hostname bastion` when initializing your SMS client.

### SSH Debugging

For troubleshooting SSH proxy issues, enable verbose debugging:

**In config file:**
```json
{
  "ssh_proxy": {
    "hostname": "bastion",
    "verbose": true
  }
}
```

**On command line:**
```bash
sms-cli send "test message" --ssh-verbose
sms-cli test --ssh-verbose
```

This will show detailed SSH tunnel creation, connection status, and any errors.

## Commands

- `sms-cli init` - Initialize client configuration and generate keys
- `sms-cli send <message>` - Send an SMS message
- `sms-cli test` - Test connection to the server
- `sms-cli gen-keypair` - Generate RSA keypair
- `sms-cli stat`

## Troubleshooting

### SSH Proxy Issues

If you're having trouble with SSH proxy connections:

1. **Test SSH connection manually**:
   ```bash
   ssh -L 8080:localhost:5000 user@bastion.example.com
   ```

2. **Check SSH key permissions**:
   ```bash
   chmod 600 ~/.ssh/id_rsa
   ```

3. **Verify SSH proxy configuration**:
   ```bash
   sms-cli test
   ```

4. **Common issues**:
   - SSH key not found or incorrect permissions
   - Bastion host not accessible
   - Firewall blocking SSH connections
   - Incorrect username or hostname

## Requirements

- Python 3.8+
- Access to an SMS Notifier server
- Valid RSA keypair (generated automatically)
- SSH client (for proxy connections)

## License

MIT License
