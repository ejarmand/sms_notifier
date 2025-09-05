# SMS Notifier Server - Docker Deployment

This guide explains how to deploy the SMS Notifier server using Docker and Docker Compose.

## Prerequisites

- Docker (version 20.10 or higher)
- Docker Compose (version 2.0 or higher)
- Twilio account with Account SID, Auth Token, and phone number


## Deployment
1. **Clone and navigate to the server directory:**
   ```bash
   cd server
   ```

2. **Set up environment variables:**
    **NOTE: I heavily avoid writing any sensitive info (e.g. auth tokens) to 
    files. Exporting them to your current shell is a reasonable alternative. 
    For particularly sensitive files you can proceed your bash command with a
    space character to exclude it from bash history (at least in defualt ubuntu
    configs)**
    ```bash
     export TWILIO_AUTH_TOKEN=[auth_token]
    ...
    ```
    *see [configuration](##configuration) for details*

3. **Create authorized_keys file:**
   ```bash
   # Add your client public keys in OpenSSH format
   echo "my-client ssh-rsa AAAAB3NzaC1yc2E... user@my-client" > authorized_keys
   ```

4. **Build with docker-compose:**
   ```bash
   docker-compose -f docker-compose.yml up --build -d
   ```

3. **Check status:**
   ```bash
   docker-compose ps
   docker-compose logs
   ```

## Configuration

### Environment Variables

#### Required
- `TWILIO_ACCOUNT_SID`: Your Twilio Account SID
- `TWILIO_AUTH_TOKEN`: Your Twilio Auth Token
- `TWILIO_PHONE_NUMBER`: Your Twilio phone number (e.g., +1234567890)
- `YOUR_PHONE_NUMBER`: Your personal phone number for receiving SMS

#### Optional
- `HOST`: Server host (default: 0.0.0.0)
- `PORT`: Server port (default: 5000)
- `DEBUG`: Enable debug mode (default: false)
- `LOG_LEVEL`: Logging level (default: INFO)
- `LOG_FILE`: Log file path (default: /app/logs/sms_notifier.log)

## Docker Services

### SMS Notifier Service

- **Image**: Built from local Dockerfile
- **Port**: 5000 (mapped to host)
- **Volumes**:
  - `./authorized_keys:/app/auth/authorized_keys:ro` - Read-only authorized keys
  - `./logs:/app/logs` - Persistent logs
  - `./data:/app/data` - Persistent database

### Nginx Service (Optional)

- **Image**: nginx:alpine
- **Ports**: 80, 443
- **Features**:
  - Reverse proxy
  - Rate limiting
  - Security headers

### Monitoring

1. **Logs**: All logs are persisted in the `./logs` directory
2. **Health Checks**: Built-in health check endpoint at `/health`
3. **Structured Logging**: Logs include structured data for monitoring


## API Endpoints

Once deployed, the following endpoints are available:

- `GET /health` - Health check
- `POST /auth/challenge` - Request authentication challenge
- `POST /auth/verify` - Verify challenge response
- `POST /sms/send` - Send SMS message

See the main README.md for detailed API documentation.
