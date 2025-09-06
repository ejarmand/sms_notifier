# SMS Notifier

A simple server deployment + python cli/library for programmatically sending
text messages. Designed around sending status udpates via sms within my vpn, with 
client ssh proxy configuration to allow api calls from servers outside my vpn.

**verbose**
This is a side project I threw together largely because verizon disabled email-sms.
More or less I just want to text myself useful script status (e.g. job failures/
completion for training. It turns out setting up a phone number for programmatic
sms sending requires government approval, so this idea was on the back burner for 
a while while twilio and the government handled my request.

During development I heavily leaned on cli coding agents (mostly cursor-agent, 
which was much more snappy and responsive). I figured I could get exposure to
docker and public key authentication, but have enough familiarity with bash, flask,
nginx, to stay out of trouble.

If you're my friend and want to send yourself sms updates, but don't want to 
go through the trouble of getting a government approved phone number 
(or deploying a server) let me know and I can probably help you configure 
a proxy connection to this api.

## Quick Start

### CLI installation

If you just want to use/configure the cli to access the endpoint:

```bash
pip install git+https://github.com/ejarmand/sms_notifier.git#subdirectory=client
```

Alternatively, I prefer:

```bash
uv tool install 'git+https://github.com/ejarmand/sms_notifier.git#subdirectory=client'
```

Configuration:

```bash
smsn-client init --server-url http://external-server:5000 \
# optional config for using an ssh proxy \
--ssh-hostname bastion
```

### Development Setup (the dev setup is greedily optimized. e.g not good at all)

**note: the dev_setup.py is a total mess, and I don't plan to update it**

```bash
# Clone the repository
git clone <repository-url>
cd sms_notifier

# Run self-contained setup (installs everything automatically)
python3 dev_setup.py

# Start debug server (no real SMS sending)
./start_server.sh

# Test the setup
./test_client.sh test
./test_client.sh send "Hello World!"
```

### Production Deployment

```bash
# Server deployment
cd server

# export environmental variables
# for more details see server/DOCKER_README.md
export TWILIO_AUTH_TOKEN=[auth_token]
...

# Add your client public keys in OpenSSH format
echo "my-client ssh-rsa AAAAB3NzaC1yc2E... user@my-client" > authorized_keys

docker-compose -f docker-compose.yml up --build -d

# Client setup
cd ../client
python3 -m sms_client.cli init
```
## API Endpoints

- `GET /health` - Health check
- `POST /auth/challenge` - Request authentication challenge
- `POST /auth/verify` - Verify challenge response
- `POST /sms/send` - Send SMS message (with authentication)

## Architecture

### Server Components

- **Authentication Blueprint** (`/auth/*`): Handles challenge generation and verification
- **SMS Blueprint** (`/sms/*`): Sends SMS messages with built-in authentication
- **Debug Server**: Mock implementation for development and testing

## Client Components

- **CLI Interface**: Command-line client with init, send, and test commands
- **API Client**: Python library for programmatic access
- **Automatic Setup**: Generates keys and configures authentication

## Development

### Package Management

This project uses `uv` for fast Python package management:
- Server: `uv sync --dev` in `server/` directory
- Client: `uv sync --dev` in `client/` directory

## Deployment

## Security
- Challenge response publickey authentication

## Documentation

- [Docker Deployment](server/DOCKER_README.md) - Container deployment guide
- [Client Documentation](server/README.md) - Client API reference

## License

MIT Liscence
