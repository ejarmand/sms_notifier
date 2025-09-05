#!/usr/bin/env python3
"""
Self-Contained Development Setup for SMS Notifier

This script sets up a complete development environment with:
- Server with mock Twilio (no real SMS sending) or real SMS
- Client configured to work with the server
- Automatic key generation and configuration
- No manual configuration required

Usage:
    python3 dev_setup.py                    # Debug mode with mock SMS, localhost only
    python3 dev_setup.py --test-sms         # Real SMS mode, localhost only
    python3 dev_setup.py --network          # Debug mode, network accessible
    python3 dev_setup.py --docker           # Build Docker image and run in container
    python3 dev_setup.py --env-file .env    # Use existing .env file
    python3 dev_setup.py --docker --inherit-env  # Pass shell env vars to Docker
    python3 dev_setup.py --no-cleanup       # Skip cleanup of temp files
    python3 dev_setup.py --test-sms --docker --inherit-env  # All flags

Options:
    --test-sms      Use real Twilio SMS instead of debug mode
    --network       Expose server to network (0.0.0.0), otherwise localhost only
    --docker        Build Docker image and run server in container
    --env-file PATH Path to existing .env file (default: create new .env file)
    --inherit-env   Pass current shell environment variables to Docker container (Docker mode only)
    --no-cleanup    Skip cleanup of temporary files on successful completion

Requirements:
    - Python 3.8+
    - uv package manager (installed automatically if missing, not needed with --docker)
    - Docker (required only when using --docker flag)
"""

import os
import sys
import subprocess
import json
import tempfile
import shutil
import atexit
import signal
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import base64
import socket

# Global variables for cleanup tracking
_cleanup_needed = False
_temp_files = []
_temp_dirs = []

def register_cleanup():
    """Register cleanup functions to run on exit"""
    # Only register signal handlers for interrupts, not atexit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    print(f"\nReceived signal {signum}, cleaning up...")
    cleanup_on_exit()
    sys.exit(1)

def cleanup_on_exit():
    """Clean up temporary files and directories"""
    global _cleanup_needed, _temp_files, _temp_dirs
    
    if not _cleanup_needed:
        return
    
    print("\n" + "="*50)
    print("Cleaning up temporary files...")
    print("="*50)
    
    # Clean up temporary files
    for temp_file in _temp_files:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                print(f"Removed temporary file: {temp_file}")
        except Exception as e:
            print(f"Warning: Could not remove {temp_file}: {e}")
    
    # Clean up temporary directories
    for temp_dir in _temp_dirs:
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                print(f"Removed temporary directory: {temp_dir}")
        except Exception as e:
            print(f"Warning: Could not remove {temp_dir}: {e}")
    
    print("Cleanup completed")

def cleanup_on_success():
    """Clean up temporary files after successful setup"""
    global _cleanup_needed, _temp_files, _temp_dirs
    
    if not _cleanup_needed:
        return
    
    print("\n" + "="*50)
    print("Setup completed successfully - cleaning up temporary files...")
    print("="*50)
    
    # Clean up temporary files
    for temp_file in _temp_files:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                print(f"Removed temporary file: {temp_file}")
        except Exception as e:
            print(f"Warning: Could not remove {temp_file}: {e}")
    
    # Clean up temporary directories
    for temp_dir in _temp_dirs:
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                print(f"Removed temporary directory: {temp_dir}")
        except Exception as e:
            print(f"Warning: Could not remove {temp_dir}: {e}")
    
    print("Cleanup completed")

def add_temp_file(file_path):
    """Add a file to the cleanup list"""
    global _temp_files
    _temp_files.append(file_path)

def add_temp_dir(dir_path):
    """Add a directory to the cleanup list"""
    global _temp_dirs
    _temp_dirs.append(dir_path)

def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result


def install_uv():
    """Install uv package manager if not present"""
    try:
        run_command(["uv", "--version"], check=False)
        print("uv is already installed")
        return True
    except FileNotFoundError:
        print("Installing uv package manager...")
        try:
            # Try to install uv
            run_command([sys.executable, "-m", "pip", "install", "uv"])
            run_command(["uv", "--version"])
            return True
        except subprocess.CalledProcessError:
            print("Failed to install uv. Please install it manually:")
            print("curl -LsSf https://astral.sh/uv/install.sh | sh")
            return False


def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def load_env_file(env_file_path):
    """Load environment variables from a .env file"""
    env_vars = {}
    if not os.path.exists(env_file_path):
        return env_vars
    
    try:
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=VALUE format
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    except Exception as e:
        print(f"Warning: Could not load .env file {env_file_path}: {e}")
    
    return env_vars

def generate_keypair():
    """Generate RSA keypair for client"""
    print("Generating RSA keypair...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key in OpenSSH format
    public_ssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    return private_pem, public_ssh


def build_docker_image():
    """Build Docker image for the server"""
    print("\n" + "="*50)
    print("Building Docker Image")
    print("="*50)
    
    server_dir = Path("server")
    if not server_dir.exists():
        print("Error: server directory not found")
        return False
    
    # Check if required files exist
    dockerfile_path = server_dir / "Dockerfile"
    requirements_path = server_dir / "requirements.txt"
    
    if not dockerfile_path.exists():
        print("Error: Dockerfile not found in server directory")
        print(f"Expected: {dockerfile_path}")
        return False
    
    if not requirements_path.exists():
        print("Error: requirements.txt not found in server directory")
        print(f"Expected: {requirements_path}")
        return False
    
    # Check if Docker is available and accessible
    try:
        result = run_command(["docker", "--version"], check=False)
        if result.returncode != 0:
            print("Error: Docker command failed")
            print("This usually means you need to run with 'sudo' or add your user to the docker group")
            print("Try: sudo usermod -aG docker $USER (then log out and back in)")
            return False
        
        # Test if we can run docker commands (check permissions)
        test_result = run_command(["docker", "ps"], check=False)
        if test_result.returncode != 0:
            print("Error: Docker daemon not accessible")
            print("This usually means you need to run with 'sudo' or add your user to the docker group")
            print("Try: sudo usermod -aG docker $USER (then log out and back in)")
            print("Or run this script with: sudo python3 dev_setup.py --docker")
            return False
            
    except FileNotFoundError:
        print("Error: Docker is not installed or not in PATH")
        print("Please install Docker and try again")
        return False
    
    # Build the Docker image
    print("Building Docker image for SMS Notifier server...")
    try:
        result = run_command(["docker", "build", "-t", "sms-notifier:dev", "."], cwd=server_dir, check=False)
        if result.returncode == 0:
            print("✓ Docker image built successfully")
            return True
        else:
            print("✗ Docker build failed with return code:", result.returncode)
            if result.stdout:
                print("STDOUT:", result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            return False
    except Exception as e:
        print(f"✗ Docker build failed with exception: {e}")
        return False


def setup_server(use_real_sms=False, expose_network=False, use_docker=False, env_file_path=None, inherit_env=False):
    """Set up the server environment"""
    print("\n" + "="*50)
    print("Setting up SMS Notifier Server")
    print("="*50)
    
    server_dir = Path("server")
    if not server_dir.exists():
        print("Error: server directory not found")
        return False
    
    if use_docker:
        print("Docker mode: Skipping Python environment setup")
        # Create necessary directories for Docker volumes
        (server_dir / "logs").mkdir(exist_ok=True)
        (server_dir / "data").mkdir(exist_ok=True)
    else:
        # Install dependencies with uv
        print("Installing server dependencies...")
        try:
            run_command(["uv", "sync", "--dev"], cwd=server_dir)
        except subprocess.CalledProcessError:
            print("Failed to install server dependencies")
            return False
        
        # Create necessary directories
        (server_dir / "logs").mkdir(exist_ok=True)
        (server_dir / "data").mkdir(exist_ok=True)
    
    # Determine host binding
    host = "0.0.0.0" if expose_network else "127.0.0.1"
    network_info = "network accessible" if expose_network else "localhost only"
    
    # Handle environment configuration
    env_file = server_dir / ".env"
    
    if inherit_env:
        # Skip .env file creation when using --inherit-env
        print("Using environment variables from shell - no .env file created")
    elif env_file_path:
        # Use existing .env file
        if not os.path.exists(env_file_path):
            print(f"Error: Specified .env file not found: {env_file_path}")
            return False
        
        print(f"Using existing .env file: {env_file_path}")
        # Copy the existing .env file to server directory
        import shutil
        shutil.copy2(env_file_path, env_file)
        
        # Load existing variables to check if we need to update HOST
        existing_env = load_env_file(env_file_path)
        if 'HOST' not in existing_env or existing_env['HOST'] != host:
            print(f"Updating HOST in .env file to {host} for {network_info} mode")
            # Read the file, update HOST, and write back
            with open(env_file, 'r') as f:
                content = f.read()
            
            # Update or add HOST line
            lines = content.split('\n')
            updated = False
            for i, line in enumerate(lines):
                if line.startswith('HOST='):
                    lines[i] = f'HOST={host}'
                    updated = True
                    break
            
            if not updated:
                lines.append(f'HOST={host}')
            
            with open(env_file, 'w') as f:
                f.write('\n'.join(lines))
    
    else:
        # the script should under no circumstances write out the current shells
        # variables, given they may contain private info (e.g. account ids, auth
        # keys)
        existing_env = {}
        # Determine SMS mode
        sms_debug_mode = "false" if use_real_sms else "true"
        sms_mode_desc = "REAL SMS" if use_real_sms else "DEBUG (mock SMS)"
        
        print(f"Configuring server for {sms_mode_desc} mode ({network_info})")
        
        # Use existing env vars or defaults
        twilio_sid = existing_env.get('TWILIO_ACCOUNT_SID', 'your_twilio_account_sid')
        twilio_token = existing_env.get('TWILIO_AUTH_TOKEN', 'your_twilio_auth_token')
        twilio_phone = existing_env.get('TWILIO_PHONE_NUMBER', 'your_twilio_phone_number')
        your_phone = existing_env.get('YOUR_PHONE_NUMBER', 'your_phone_number')
        port = existing_env.get('PORT', '5000')
        debug = existing_env.get('DEBUG', 'true')
        log_level = existing_env.get('LOG_LEVEL', 'DEBUG')
        
        env_content = f"""# SMS Notifier Development Environment
# Set your actual Twilio credentials as environment variables:
# export TWILIO_ACCOUNT_SID=your_actual_sid
# export TWILIO_AUTH_TOKEN=your_actual_token
# export TWILIO_PHONE_NUMBER=your_twilio_phone
# export YOUR_PHONE_NUMBER=your_phone_number

TWILIO_ACCOUNT_SID={twilio_sid}
TWILIO_AUTH_TOKEN={twilio_token}
TWILIO_PHONE_NUMBER={twilio_phone}
YOUR_PHONE_NUMBER={your_phone}
HOST={host}
PORT={port}
DEBUG={debug}
LOG_LEVEL={log_level}
SMS_DEBUG_MODE={sms_debug_mode}
SMSN_DATABASE_PATH=./data/auth_challenge.db
SMSN_AUTHORIZED_KEYS_PATH=./authorized_keys
"""
        
        with open(env_file, "w") as f:
            f.write(env_content)
    
    print("Server setup complete")
    return True


def setup_client(expose_network=False, use_docker=False):
    """Set up the client environment"""
    print("\n" + "="*50)
    print("Setting up SMS Notifier Client")
    print("="*50)
    
    client_dir = Path("client")
    if not client_dir.exists():
        print("Error: client directory not found")
        return False
    
    # Install dependencies with uv
    print("Installing client dependencies...")
    try:
        run_command(["uv", "sync", "--dev"], cwd=client_dir)
    except subprocess.CalledProcessError:
        print("Failed to install client dependencies")
        return False
    
    # Generate keypair
    private_pem, public_ssh = generate_keypair()
    
    # Create client config directory
    config_dir = client_dir / "dev_config"
    config_dir.mkdir(exist_ok=True)
    add_temp_dir(str(config_dir))
    
    # Write private key
    private_key_path = config_dir / "id_rsa"
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_key_path, 0o600)
    add_temp_file(str(private_key_path))
    
    # Write public key
    public_key_path = config_dir / "id_rsa.pub"
    hostname = socket.gethostname()
    public_line = public_ssh + b" " + hostname.encode("utf-8") + b"\n"
    with open(public_key_path, "wb") as f:
        f.write(public_line)
    add_temp_file(str(public_key_path))
    
    # Create client config - use appropriate IP based on server binding mode
    if use_docker:
        # Docker mode: container exposes port to host, so client connects to localhost
        server_ip = "127.0.0.1"
        network_mode = "Docker container (localhost)"
    elif expose_network:
        # Server binds to 0.0.0.0, so client should connect to actual local IP
        server_ip = get_local_ip()
        network_mode = "network accessible"
    else:
        # Server binds to 127.0.0.1, so client should connect to localhost
        server_ip = "127.0.0.1"
        network_mode = "localhost only"
    
    config_data = {
        "server_url": f"http://{server_ip}:5000",
        "hostname": hostname,
        "private_key_path": str(private_key_path.absolute())
    }
    
    config_path = config_dir / "config.json"
    with open(config_path, "w") as f:
        json.dump(config_data, f, indent=2)
    add_temp_file(str(config_path))
    
    print(f"Client config created: {config_path}")
    print(f"Server URL: {config_data['server_url']} ({network_mode})")
    print("Phone routing: Server will use default phone number")
    print(f"Private key: {private_key_path}")
    print(f"Public key: {public_key_path}")
    
    return config_path, public_key_path


def setup_server_authorized_keys(public_key_path):
    """Add client public key to server authorized_keys"""
    print("\n" + "="*50)
    print("Configuring Server Authentication")
    print("="*50)
    
    server_dir = Path("server")
    authorized_keys_path = server_dir / "authorized_keys"
    
    # Read the public key
    with open(public_key_path, "rb") as f:
        public_key_content = f.read().decode("utf-8").strip()
    
    # Write to server authorized_keys
    with open(authorized_keys_path, "w") as f:
        f.write(public_key_content + "\n")
    add_temp_file(str(authorized_keys_path))
    
    print(f"Added client public key to: {authorized_keys_path}")
    return True


def create_startup_scripts(config_path, use_docker=False, use_real_sms=False, expose_network=False, env_file_path=None, inherit_env=False):
    """Create convenient startup scripts"""
    print("\n" + "="*50)
    print("Creating Startup Scripts")
    print("="*50)
    
    # Server startup script
    if use_docker:
        # Determine port binding for Docker
        port_binding = "127.0.0.1:5000:5000" if not expose_network else "5000:5000"
        
        if inherit_env:
            # Pass environment variables from shell to container
            env_info = "Using environment variables from current shell"
            env_args = "-e TWILIO_ACCOUNT_SID -e TWILIO_AUTH_TOKEN -e TWILIO_PHONE_NUMBER -e YOUR_PHONE_NUMBER -e HOST -e PORT -e DEBUG -e LOG_LEVEL"
        else:
            # Use .env file
            if env_file_path:
                env_volume = f"-v \"{os.path.abspath(env_file_path)}:/app/.env:ro\""
                env_info = f"Using .env file: {env_file_path}"
                env_args = ""
            else:
                env_volume = "-v \"$(pwd)/.env:/app/.env:ro\""
                env_info = "Using .env file: server/.env"
                env_args = ""
        
        if inherit_env:
            server_script = f"""#!/bin/bash
cd server

# Stop any existing container
docker stop sms-notifier-dev 2>/dev/null || true
docker rm sms-notifier-dev 2>/dev/null || true

# Run the Docker container with environment variables from shell
docker run -d \\
    --name sms-notifier-dev \\
    -p {port_binding} \\
    -v "$(pwd)/logs:/app/logs" \\
    -v "$(pwd)/data:/app/data" \\
    -v "$(pwd)/authorized_keys:/app/auth/authorized_keys:ro" \\
    {env_args} \\
    sms-notifier:dev

echo "SMS Notifier server started in Docker container"
echo "Container name: sms-notifier-dev"
echo "Server URL: http://127.0.0.1:5000"
echo "{env_info}"
echo ""
echo "To view logs: docker logs -f sms-notifier-dev"
echo "To stop: docker stop sms-notifier-dev"
"""
        else:
            server_script = f"""#!/bin/bash
cd server

# Stop any existing container
docker stop sms-notifier-dev 2>/dev/null || true
docker rm sms-notifier-dev 2>/dev/null || true

# Run the Docker container
docker run -d \\
    --name sms-notifier-dev \\
    -p {port_binding} \\
    -v "$(pwd)/logs:/app/logs" \\
    -v "$(pwd)/data:/app/data" \\
    -v "$(pwd)/authorized_keys:/app/auth/authorized_keys:ro" \\
    {env_volume} \\
    sms-notifier:dev

echo "SMS Notifier server started in Docker container"
echo "Container name: sms-notifier-dev"
echo "Server URL: http://127.0.0.1:5000"
echo "{env_info}"
echo ""
echo "To view logs: docker logs -f sms-notifier-dev"
echo "To stop: docker stop sms-notifier-dev"
"""
    else:
        server_script = """#!/bin/bash
cd server

# Environment variables are loaded automatically by the application
uv run python sms_notifier.py
"""
    
    with open("start_server.sh", "w") as f:
        f.write(server_script)
    os.chmod("start_server.sh", 0o755)
    add_temp_file("start_server.sh")
    
    # Client test script
    client_script = f"""#!/bin/bash
cd client
uv run python -m sms_client.cli "$@" --config {os.path.relpath(config_path, 'client')} 
"""
    
    with open("test_client.sh", "w") as f:
        f.write(client_script)
    os.chmod("test_client.sh", 0o755)
    add_temp_file("test_client.sh")
    
    print("Created startup scripts:")
    print("  start_server.sh - Start debug server")
    print("  test_client.sh - Test client commands")
    
    return True


def test_setup():
    """Test the complete setup"""
    print("\n" + "="*50)
    print("Testing Setup")
    print("="*50)
    
    # Test that required files exist
    required_files = [
        "server/sms_notifier.py",
        "server/authorized_keys", 
        "client/dev_config/config.json",
        "client/dev_config/id_rsa",
        "client/dev_config/id_rsa.pub",
        "start_server.sh",
        "test_client.sh"
    ]
    
    for file_path in required_files:
        if not Path(file_path).exists():
            print(f"✗ Missing required file: {file_path}")
            return False
        else:
            print(f"✓ Found: {file_path}")
    
    print("✓ Setup test completed successfully")
    return True


def main():
    """Main setup function"""
    global _cleanup_needed
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Setup SMS Notifier development environment")
    parser.add_argument("--no-cleanup", action="store_true", 
                       help="Skip cleanup of temporary files on successful completion")
    parser.add_argument("--test-sms", action="store_true",
                       help="Use real Twilio SMS instead of debug mode")
    parser.add_argument("--network", action="store_true",
                       help="Expose server to network (0.0.0.0), otherwise localhost only")
    parser.add_argument("--docker", action="store_true",
                       help="Build Docker image and run server in container")
    parser.add_argument("--env-file", type=str, metavar="PATH",
                       help="Path to existing .env file (default: create new .env file)")
    parser.add_argument("--inherit-env", action="store_true",
                       help="Pass current shell environment variables to Docker container (Docker mode only)")
    
    args = parser.parse_args()
    
    # Validate argument combinations
    if args.inherit_env and not args.docker:
        print("Error: --inherit-env can only be used with --docker flag")
        sys.exit(1)
    
    # Register cleanup handlers
    register_cleanup()
    
    print("SMS Notifier - Self-Contained Development Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"Python version: {sys.version}")
    
    # Mark that cleanup is needed
    _cleanup_needed = True
    
    # Install uv if needed (skip for Docker mode)
    if not args.docker and not install_uv():
        sys.exit(1)
    
    # Build Docker image if requested
    if args.docker and not build_docker_image():
        print("Failed to build Docker image")
        sys.exit(1)
    
    # Set up server
    if not setup_server(use_real_sms=args.test_sms, expose_network=args.network, use_docker=args.docker, env_file_path=args.env_file, inherit_env=args.inherit_env):
        print("Failed to set up server")
        sys.exit(1)
    
    # Set up client
    result = setup_client(expose_network=args.network, use_docker=args.docker)
    if not result:
        print("Failed to set up client")
        sys.exit(1)
    
    config_path, public_key_path = result
    
    # Configure server authentication
    if not setup_server_authorized_keys(public_key_path):
        print("Failed to configure server authentication")
        sys.exit(1)
    
    # Create startup scripts
    if not create_startup_scripts(config_path, use_docker=args.docker, use_real_sms=args.test_sms, expose_network=args.network, env_file_path=args.env_file, inherit_env=args.inherit_env):
        print("Failed to create startup scripts")
        sys.exit(1)
    
    # Test setup
    if not test_setup():
        print("Setup test failed")
        sys.exit(1)
    
    # Success message
    print("\n" + "="*60)
    print("Development Setup Complete!")
    print("="*60)
    print()
    print("Quick Start:")
    print("1. Start server: ./start_server.sh")
    print("2. Test client: ./test_client.sh test")
    print("3. Send SMS: ./test_client.sh send 'Hello World!'")
    print()
    if args.docker:
        print("Server will be available at: http://127.0.0.1:5000 (Docker container)")
        print("Debug info: http://127.0.0.1:5000/debug/info")
        print("Container logs: docker logs -f sms-notifier-dev")
    elif args.network:
        print("Server will be available at: http://0.0.0.0:5000 (network accessible)")
        print("Debug info: http://0.0.0.0:5000/debug/info")
    else:
        print("Server will be available at: http://127.0.0.1:5000 (localhost only)")
        print("Debug info: http://127.0.0.1:5000/debug/info")
    print()
    print("Features:")
    print("- Real authentication using RSA challenge-response")
    if args.docker:
        print("- Docker containerized server")
    if args.test_sms:
        print("- REAL SMS sending (configure your Twilio credentials)")
        print("- Make sure to update server/.env with your Twilio details")
    else:
        print("- Mock SMS sending (no real SMS messages)")
    print("- Complete API testing without external dependencies")
    
    # Show network configuration
    if args.docker:
        print("- Docker container (127.0.0.1:5000)")
    elif args.network:
        print("- Network accessible (0.0.0.0:5000)")
    else:
        print("- Localhost only (127.0.0.1:5000)")
    print()
    
    # Clean up temporary files after successful setup (unless --no-cleanup is specified)
    if not args.no_cleanup:
        print("Note: Temporary files will be cleaned up after successful setup.")
        print("If setup fails, files are preserved for debugging.")
        cleanup_on_success()
    else:
        print("Note: Cleanup skipped (--no-cleanup flag used)")
        print("Temporary files preserved for inspection.")


if __name__ == "__main__":
    main()
