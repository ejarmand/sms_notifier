import argparse
import os
import sys
import json
import subprocess
import shlex
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from .sms_api_caller import SMSAPIConfig, SMSAPIClient


def generate_keypair(bits: int = 3072) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_ssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return private_pem, public_ssh


def write_file(path: str, data: bytes, mode: int = 0o600) -> None:
    with open(path, 'wb') as f:
        f.write(data)
    try:
        os.chmod(path, mode)
    except Exception:
        # Ignore chmod issues on non-POSIX
        pass


def cmd_gen_keypair(args: argparse.Namespace) -> int:
    private_pem, public_ssh = generate_keypair(bits=args.bits)
    comment = args.comment or os.uname().nodename
    public_line = public_ssh + b" " + comment.encode("utf-8") + b"\n"

    write_file(args.private_out, private_pem, 0o600)
    write_file(args.public_out, public_line, 0o644)

    print(f"Wrote private key to {args.private_out}")
    print(f"Wrote public key to {args.public_out}")
    return 0


def cmd_send_sms(args: argparse.Namespace) -> int:
    """Send an SMS message"""
    try:
        config = SMSAPIConfig(args.config)
        
        # Override SSH verbose setting if specified on command line
        if args.ssh_verbose:
            config.ssh_verbose = True
        
        with SMSAPIClient(config) as client:
            response = client.send_sms(args.message, args.to)
            
            if args.verbose:
                print(json.dumps(response, indent=2))
            else:
                print(f"SMS sent successfully! Message ID: {response.get('message_id', 'N/A')}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_test_connection(args: argparse.Namespace) -> int:
    """Test connection to SMS API"""
    try:
        config = SMSAPIConfig(args.config)
        
        # Override SSH verbose setting if specified on command line
        if args.ssh_verbose:
            config.ssh_verbose = True
        
        with SMSAPIClient(config) as client:
            # Try to get a challenge
            challenge = client.get_challenge()
            print(f"Connection successful! Got challenge: {challenge[:16]}...")
        return 0
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return 1


def cmd_stat(args: argparse.Namespace) -> int:
    """Execute a command and send SMS notification with exit status"""
    try:
        config = SMSAPIConfig(args.config)
        
        # Override SSH verbose setting if specified on command line
        if args.ssh_verbose:
            config.ssh_verbose = True
        
        # Determine the command to execute
        command = args.command
                
        # Execute the command
        if args.verbose:
            print(f"Executing command: {command}")
        
        try:
            # Use shell=True to support complex commands with pipes, redirects, etc.
            result = subprocess.run(
                command,
                shell=True,
            )
            exit_code = result.returncode
            
            if args.verbose:
                print(f"Command exit code: {exit_code}")
                if result.stdout:
                    print(f"Command stdout: {result.stdout}")
                if result.stderr:
                    print(f"Command stderr: {result.stderr}")
            
        except Exception as e:
            exit_code = 125  # Standard execution error exit code
            if args.verbose:
                print(f"Command execution failed: {e}")
        
        # Determine success/failure and create message
        hostname = config.hostname
        if exit_code == 0 and args.message_on in ['success', 'both']:
            status = "completed successfully"
            message = f"Command '{command}' on {hostname} {status}"
        elif args.message_on in ['fail', 'both']:
            status = f"failed with exit code {exit_code}"
            message = f"Command '{command}' on {hostname} {status}"
        else:
            return exit_code
        # Send SMS notification
        with SMSAPIClient(config) as client:
            response = client.send_sms(message, args.to)
            
            if args.verbose:
                print(json.dumps(response, indent=2))
            else:
                print(f"SMS notification sent: {message}")
        
        # Return the same exit code as the executed command
        return exit_code
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def get_default_config_dir() -> str:
    """Get the default configuration directory following XDG standards"""
    # Try XDG_CONFIG_HOME first
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return os.path.join(xdg_config_home, "sms_notifier")
    
    # Fall back to HOME/.config/sms_notifier
    home = os.environ.get("HOME")
    if home:
        return os.path.join(home, ".config", "sms_notifier")
    
    # Last resort: current directory
    return os.path.join(os.getcwd(), ".config", "sms_notifier")


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize SMS client - creates config directory, generates keys, and creates config"""
    config_dir = args.config_dir or get_default_config_dir()
    config_path = os.path.join(config_dir, "config.json")
    private_key_path = os.path.join(config_dir, "id_rsa")
    public_key_path = os.path.join(config_dir, "id_rsa.pub")
    
    print(f"Initializing SMS client in: {config_dir}")
    
    # Create config directory
    try:
        os.makedirs(config_dir, exist_ok=True)
        print(f"Created config directory: {config_dir}")
    except Exception as e:
        print(f"Failed to create config directory: {e}", file=sys.stderr)
        return 1
    
    # Check if files already exist
    existing_files = []
    if os.path.exists(config_path):
        existing_files.append("config.json")
    if os.path.exists(private_key_path):
        existing_files.append("id_rsa")
    if os.path.exists(public_key_path):
        existing_files.append("id_rsa.pub")
    
    if existing_files and not args.force:
        print(f"Files already exist: {', '.join(existing_files)}")
        print("Use --force to overwrite existing files")
        return 1
    
    # Generate keypair
    try:
        print("Generating RSA keypair...")
        private_pem, public_ssh = generate_keypair(bits=args.bits)
        hostname = args.hostname or os.uname().nodename
        public_line = public_ssh + b" " + hostname.encode("utf-8") + b"\n"
        
        write_file(private_key_path, private_pem, 0o600)
        write_file(public_key_path, public_line, 0o644)
        print(f"Generated keypair:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key:  {public_key_path}")
    except Exception as e:
        print(f"Failed to generate keypair: {e}", file=sys.stderr)
        return 1
    
    # Create config file
    try:
        print("Creating config file...")
        config_data = {
            "server_url": args.server_url or "http://localhost:5000",
            "hostname": hostname,
            "private_key_path": private_key_path,
            "to_number": args.to_number
        }
        
        # Add SSH proxy configuration if provided
        ssh_proxy_config = {}
        
        # SSH hostname takes precedence - loads from ~/.ssh/config
        if args.ssh_hostname:
            ssh_proxy_config["hostname"] = args.ssh_hostname
        else:
            # Manual SSH proxy configuration
            if args.ssh_proxy_host:
                ssh_proxy_config["host"] = args.ssh_proxy_host
            if args.ssh_proxy_port != 22:
                ssh_proxy_config["port"] = args.ssh_proxy_port
            if args.ssh_proxy_user:
                ssh_proxy_config["user"] = args.ssh_proxy_user
            if args.ssh_proxy_key:
                ssh_proxy_config["key"] = args.ssh_proxy_key
            if args.ssh_proxy_jump:
                ssh_proxy_config["jump"] = args.ssh_proxy_jump
            if args.ssh_verbose:
                ssh_proxy_config["verbose"] = True
        
        if ssh_proxy_config:
            config_data["ssh_proxy"] = ssh_proxy_config
        
        # Remove None values
        config_data = {k: v for k, v in config_data.items() if v is not None}
        
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        print(f"Created config file: {config_path}")
        if ssh_proxy_config:
            if args.ssh_hostname:
                print(f"SSH configuration loaded from ~/.ssh/config for hostname: {args.ssh_hostname}")
            else:
                print("SSH proxy configuration added to config file")
    except Exception as e:
        print(f"Failed to create config file: {e}", file=sys.stderr)
        return 1
    
    print("\nSMS client initialized successfully!")
    
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sms-cli", description="SMS Notifier client utilities")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Initialize everything command (main command)
    p_init = sub.add_parser("init", help="Initialize SMS client (creates config, generates keys)", description="Initialize SMS client by creating configuration directory, generating RSA keypair, and setting up config file with default settings.")
    p_init.add_argument("--config-dir", help="Config directory (default: XDG_CONFIG_HOME/sms_notifier or ~/.config/sms_notifier)")
    p_init.add_argument("--server-url", help="SMS API server URL (default: http://localhost:5000)")
    p_init.add_argument("--hostname", help="Client hostname (default: system hostname)")
    p_init.add_argument("--to-number", help="Default recipient phone number")
    p_init.add_argument("--bits", type=int, default=3072, help="RSA key size in bits (default: 3072)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing files")
    
    # SSH proxy options
    ssh_group = p_init.add_argument_group("SSH proxy options", "Configure SSH tunnel for external servers")
    ssh_group.add_argument("--ssh-hostname", help="SSH hostname from ~/.ssh/config (loads all SSH settings automatically)")
    ssh_group.add_argument("--ssh-proxy-host", help="SSH proxy hostname for external servers")
    ssh_group.add_argument("--ssh-proxy-port", type=int, default=22, help="SSH proxy port (default: 22)")
    ssh_group.add_argument("--ssh-proxy-user", help="SSH proxy username")
    ssh_group.add_argument("--ssh-proxy-key", help="SSH proxy private key path")
    ssh_group.add_argument("--ssh-proxy-jump", help="SSH ProxyJump configuration (e.g., user@bastion:port)")
    ssh_group.add_argument("--ssh-verbose", action="store_true", help="Enable verbose SSH proxy debugging output")
    
    p_init.set_defaults(func=cmd_init)

    # Generate keypair command
    p_gen = sub.add_parser("gen-keypair", help="Generate an RSA keypair", description="Generate a new RSA keypair for authentication with the SMS API server.")
    p_gen.add_argument("--bits", type=int, default=3072, help="Key size in bits (default: 3072)")
    p_gen.add_argument("--private-out", default="id_rsa", help="Path to write the private key (PEM) (default: id_rsa)")
    p_gen.add_argument("--public-out", default="id_rsa.pub", help="Path to write the public key (OpenSSH) (default: id_rsa.pub)")
    p_gen.add_argument("--comment", default=None, help="Public key comment (default: system hostname)")
    p_gen.set_defaults(func=cmd_gen_keypair)

    # Send SMS command
    p_send = sub.add_parser("send", help="Send an SMS message", description="Send an SMS message to a specified phone number using the configured SMS API.")
    p_send.add_argument("message", help="Message to send")
    p_send.add_argument("--to", help="Recipient phone number (overrides config)")
    p_send.add_argument("--config", default=None, help="Config file path (default: auto-detect from config directory)")
    p_send.add_argument("--verbose", "-v", action="store_true", help="Verbose output (default: False)")
    p_send.add_argument("--ssh-verbose", action="store_true", help="Enable verbose SSH proxy debugging output")
    p_send.set_defaults(func=cmd_send_sms)

    # Test connection command
    p_test = sub.add_parser("test", help="Test connection to SMS API", description="Test the connection to the SMS API server by requesting a challenge.")
    p_test.add_argument("--config", default=None, help="Config file path (default: auto-detect from config directory)")
    p_test.add_argument("--ssh-verbose", action="store_true", help="Enable verbose SSH proxy debugging output")
    p_test.set_defaults(func=cmd_test_connection)

    # Stat command - execute command and send SMS notification
    p_stat = sub.add_parser("stat", help="Execute command and send SMS notification with exit status usage:"
                            "smsn_cli stat [args] command",
                            description="Execute a command and send an SMS notification indicating whether"
                            " the command completed successfully or failed with its exit code.")
    p_stat.add_argument("--to", help="Recipient phone number (overrides config)")
    p_stat.add_argument("--config", default=None, help="Config file path (default: auto-detect from config directory)")
    p_stat.add_argument("--message-on", default="both", help="Sends message on 'success', 'fail', or default: 'both'")
    p_stat.add_argument("--verbose", "-v", action="store_true", help="Verbose output (default: False)")
    p_stat.add_argument("--ssh-verbose", action="store_true", help="Enable verbose SSH proxy debugging output")
    p_stat.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    p_stat.set_defaults(func=cmd_stat)

    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

