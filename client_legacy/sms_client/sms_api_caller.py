"""
SMS API Client Module

This module provides functionality to send SMS messages through the SMS Notifier API
using public key authentication.
"""

import os
import json
import base64
import requests
import subprocess
import socket
import time
import threading
import re
from typing import Dict, Optional, Tuple, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class SSHConfigParser:
    """Simple SSH config file parser"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            # Use default SSH config path
            home = os.environ.get("HOME")
            if home:
                config_path = os.path.join(home, ".ssh", "config")
            else:
                config_path = os.path.expanduser("~/.ssh/config")
        
        self.config_path = config_path
        self._hosts = {}
        self._load_config()
    
    def _load_config(self):
        """Load SSH config file"""
        if not os.path.exists(self.config_path):
            return
        
        try:
            with open(self.config_path, 'r') as f:
                content = f.read()
            
            self._parse_config(content)
        except Exception:
            # Ignore parsing errors - SSH config might be malformed
            pass
    
    def _parse_config(self, content: str):
        """Parse SSH config content"""
        lines = content.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Parse key-value pairs
            if ' ' in line:
                key, value = line.split(' ', 1)
                key = key.lower()
                value = value.strip()
                
                if key == 'host':
                    # New host entry
                    current_host = value
                    if current_host not in self._hosts:
                        self._hosts[current_host] = {}
                elif current_host and key in ['hostname', 'port', 'user', 'identityfile', 'proxyjump']:
                    # Add to current host
                    if key == 'identityfile':
                        # Handle multiple identity files
                        if 'identityfile' not in self._hosts[current_host]:
                            self._hosts[current_host]['identityfile'] = []
                        self._hosts[current_host]['identityfile'].append(value)
                    else:
                        self._hosts[current_host][key] = value
    
    def get_host_config(self, hostname: str) -> Dict[str, str]:
        """Get configuration for a specific host"""
        # Try exact match first
        if hostname in self._hosts:
            return self._hosts[hostname].copy()
        
        # Try pattern matching (simple wildcard support)
        for pattern, config in self._hosts.items():
            if self._match_pattern(hostname, pattern):
                return config.copy()
        
        return {}
    
    def _match_pattern(self, hostname: str, pattern: str) -> bool:
        """Simple pattern matching for SSH config"""
        if '*' in pattern:
            # Convert SSH wildcard to regex
            regex_pattern = pattern.replace('*', '.*')
            return bool(re.match(f'^{regex_pattern}$', hostname))
        return False


class SMSAPIConfig:
    """Configuration for SMS API client"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            # Try environment variable first
            config_path = os.environ.get("SMS_API_CONFIG")
            if config_path is None:
                # Use XDG-compliant default path
                xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
                if xdg_config_home:
                    config_path = os.path.join(xdg_config_home, "sms_notifier", "config.json")
                else:
                    home = os.environ.get("HOME")
                    if home:
                        config_path = os.path.join(home, ".config", "sms_notifier", "config.json")
                    else:
                        config_path = os.path.join(os.getcwd(), ".config", "sms_notifier", "config.json")
        
        self.config_path = config_path
        self.server_url: str = ""
        self.hostname: str = ""
        self.private_key_path: str = ""
        self.to_number: Optional[str] = None
        
        # SSH proxy configuration
        self.ssh_proxy_host: Optional[str] = None
        self.ssh_proxy_port: int = 22
        self.ssh_proxy_user: Optional[str] = None
        self.ssh_proxy_key: Optional[str] = None
        self.ssh_proxy_jump: Optional[str] = None  # For ProxyJump-style configuration
        self.ssh_hostname: Optional[str] = None  # SSH config hostname
        self.ssh_verbose: bool = False  # Verbose SSH output
        
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            config_data = json.load(f)
        
        required_fields = ['server_url', 'hostname', 'private_key_path']
        for field in required_fields:
            if field not in config_data:
                raise ValueError(f"Missing required config field: {field}")
            setattr(self, field, config_data[field])
        
        # Optional fields
        self.to_number = config_data.get('to_number')
        
        # SSH proxy configuration (optional)
        ssh_config = config_data.get('ssh_proxy', {})
        self.ssh_proxy_host = ssh_config.get('host')
        self.ssh_proxy_port = ssh_config.get('port', 22)
        self.ssh_proxy_user = ssh_config.get('user')
        self.ssh_proxy_key = ssh_config.get('key')
        self.ssh_proxy_jump = ssh_config.get('jump')
        self.ssh_hostname = ssh_config.get('hostname')
        self.ssh_verbose = ssh_config.get('verbose', False)
        
        # If SSH hostname is provided, load SSH config
        if self.ssh_hostname:
            self._load_ssh_config()
        elif self.ssh_proxy_host or self.ssh_proxy_jump:
            # Only try to auto-detect if there's already some SSH proxy configuration
            self._auto_detect_ssh_proxy()
        else:
            # Check if server URL indicates we need SSH proxy (not localhost)
            self._check_if_ssh_needed()
    
    def _load_ssh_config(self):
        """Load SSH configuration from ~/.ssh/config"""
        try:
            ssh_parser = SSHConfigParser()
            ssh_config = ssh_parser.get_host_config(self.ssh_hostname)
            
            if ssh_config:
                # Override with SSH config values if not explicitly set
                if not self.ssh_proxy_host and 'hostname' in ssh_config:
                    self.ssh_proxy_host = ssh_config['hostname']
                
                if not self.ssh_proxy_user and 'user' in ssh_config:
                    self.ssh_proxy_user = ssh_config['user']
                
                if not self.ssh_proxy_key and 'identityfile' in ssh_config:
                    # Use the first identity file
                    identity_files = ssh_config['identityfile']
                    if isinstance(identity_files, list) and identity_files:
                        self.ssh_proxy_key = identity_files[0]
                    elif isinstance(identity_files, str):
                        self.ssh_proxy_key = identity_files
                
                if not self.ssh_proxy_jump and 'proxyjump' in ssh_config:
                    self.ssh_proxy_jump = ssh_config['proxyjump']
                
                if 'port' in ssh_config:
                    try:
                        self.ssh_proxy_port = int(ssh_config['port'])
                    except ValueError:
                        pass  # Keep default port if parsing fails
                        
        except Exception:
            # Ignore SSH config loading errors
            pass
    
    def _auto_detect_ssh_proxy(self):
        """Auto-detect SSH proxy configuration from server URL"""
        # This method is called when there's already some SSH proxy configuration
        # For now, we'll leave SSH proxy configuration as-is
        # This allows the client to work with existing SSH proxy settings
        pass
    
    def _check_if_ssh_needed(self):
        """Check if SSH proxy is needed based on server URL"""
        import urllib.parse
        
        parsed = urllib.parse.urlparse(self.server_url)
        host = parsed.hostname or 'localhost'
        
        # Only suggest SSH proxy for non-localhost servers
        if host not in ['localhost', '127.0.0.1', '::1']:
            if self.ssh_verbose:
                print(f"DEBUG: Server URL {self.server_url} points to non-localhost ({host})")
                print("DEBUG: Consider configuring SSH proxy if server is not directly accessible")
        else:
            if self.ssh_verbose:
                print(f"DEBUG: Server URL {self.server_url} points to localhost, no SSH proxy needed")


class SMSAPIClient:
    """Client for SMS Notifier API"""
    
    def __init__(self, config: SMSAPIConfig):
        self.config = config
        self._private_key = None
        self._ssh_tunnel = None
        self._tunnel_process = None
        self._tunnel_lock = threading.Lock()
    
    def _load_private_key(self):
        """Load private key from file"""
        if self._private_key is None:
            if not os.path.exists(self.config.private_key_path):
                raise FileNotFoundError(f"Private key not found: {self.config.private_key_path}")
            
            with open(self.config.private_key_path, 'rb') as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        return self._private_key
    
    def _find_free_port(self) -> int:
        """Find a free local port for SSH tunnel"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def _parse_server_url(self, url: str) -> tuple:
        """Parse server URL to extract host and port"""
        import urllib.parse
        
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return host, port
    
    def _create_ssh_tunnel(self) -> int:
        """Create SSH tunnel and return local port"""
        if not self.config.ssh_proxy_host:
            if self.config.ssh_verbose:
                print("DEBUG: No SSH proxy host configured, using direct connection")
            return None
        
        with self._tunnel_lock:
            if self._tunnel_process is not None:
                if self.config.ssh_verbose:
                    print(f"DEBUG: Reusing existing SSH tunnel on port {self._ssh_tunnel}")
                return self._ssh_tunnel
            
            # Find a free local port
            local_port = self._find_free_port()
            
            # Parse the target server from the server URL
            target_host, target_port = self._parse_server_url(self.config.server_url)
            
            if self.config.ssh_verbose:
                print(f"DEBUG: Creating SSH tunnel on local port {local_port}")
                print(f"DEBUG: SSH proxy host: {self.config.ssh_proxy_host}")
                print(f"DEBUG: SSH proxy port: {self.config.ssh_proxy_port}")
                print(f"DEBUG: SSH proxy user: {self.config.ssh_proxy_user}")
                print(f"DEBUG: SSH proxy key: {self.config.ssh_proxy_key}")
                print(f"DEBUG: SSH proxy jump: {self.config.ssh_proxy_jump}")
                print(f"DEBUG: Target server: {target_host}:{target_port}")
                print(f"DEBUG: Server URL: {self.config.server_url}")
            
            # Build SSH command with correct target
            ssh_cmd = ['ssh', '-N', '-L', f'{local_port}:{target_host}:{target_port}']
            
            # Add verbose flag if requested
            if self.config.ssh_verbose:
                ssh_cmd.append('-v')
                print(f"DEBUG: SSH command: {' '.join(ssh_cmd)}")
            
            # Add ProxyJump if specified
            if self.config.ssh_proxy_jump:
                ssh_cmd.extend(['-J', self.config.ssh_proxy_jump])
                if self.config.ssh_verbose:
                    print(f"DEBUG: Using ProxyJump: {self.config.ssh_proxy_jump}")
            
            # Add user if specified
            if self.config.ssh_proxy_user:
                ssh_cmd.extend(['-l', self.config.ssh_proxy_user])
                if self.config.ssh_verbose:
                    print(f"DEBUG: Using SSH user: {self.config.ssh_proxy_user}")
            
            # Add SSH key if specified
            if self.config.ssh_proxy_key:
                ssh_cmd.extend(['-i', self.config.ssh_proxy_key])
                if self.config.ssh_verbose:
                    print(f"DEBUG: Using SSH key: {self.config.ssh_proxy_key}")
            
            # Add port if not default
            if self.config.ssh_proxy_port != 22:
                ssh_cmd.extend(['-p', str(self.config.ssh_proxy_port)])
                if self.config.ssh_verbose:
                    print(f"DEBUG: Using SSH port: {self.config.ssh_proxy_port}")
            
            # Add hostname
            ssh_cmd.append(self.config.ssh_proxy_host)
            
            if self.config.ssh_verbose:
                print(f"DEBUG: Final SSH command: {' '.join(ssh_cmd)}")
                print("DEBUG: Starting SSH tunnel process...")
            
            try:
                # Start SSH tunnel process
                self._tunnel_process = subprocess.Popen(
                    ssh_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                
                if self.config.ssh_verbose:
                    print("DEBUG: SSH tunnel process started, waiting for connection...")
                
                # Wait a moment for tunnel to establish
                time.sleep(2)
                
                # Check if process is still running
                if self._tunnel_process.poll() is not None:
                    stdout, stderr = self._tunnel_process.communicate()
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    if self.config.ssh_verbose:
                        print(f"DEBUG: SSH tunnel process exited with code {self._tunnel_process.returncode}")
                        print(f"DEBUG: SSH stderr: {error_msg}")
                    raise Exception(f"SSH tunnel failed: {error_msg}")
                
                self._ssh_tunnel = local_port
                if self.config.ssh_verbose:
                    print(f"DEBUG: SSH tunnel established successfully on port {local_port}")
                    print(f"DEBUG: Traffic will be forwarded from localhost:{local_port} to {target_host}:{target_port} via {self.config.ssh_proxy_host}")
                
                return local_port
                
            except Exception as e:
                self._tunnel_process = None
                if self.config.ssh_verbose:
                    print(f"DEBUG: SSH tunnel creation failed: {e}")
                raise Exception(f"Failed to create SSH tunnel: {e}")
    
    def _cleanup_ssh_tunnel(self):
        """Clean up SSH tunnel"""
        with self._tunnel_lock:
            if self._tunnel_process is not None:
                if self.config.ssh_verbose:
                    print(f"DEBUG: Cleaning up SSH tunnel on port {self._ssh_tunnel}")
                try:
                    self._tunnel_process.terminate()
                    self._tunnel_process.wait(timeout=5)
                    if self.config.ssh_verbose:
                        print("DEBUG: SSH tunnel process terminated gracefully")
                except subprocess.TimeoutExpired:
                    if self.config.ssh_verbose:
                        print("DEBUG: SSH tunnel process didn't terminate, killing it")
                    self._tunnel_process.kill()
                except Exception as e:
                    if self.config.ssh_verbose:
                        print(f"DEBUG: Error during SSH tunnel cleanup: {e}")
                finally:
                    self._tunnel_process = None
                    self._ssh_tunnel = None
                    if self.config.ssh_verbose:
                        print("DEBUG: SSH tunnel cleanup completed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup SSH tunnel"""
        self._cleanup_ssh_tunnel()
    
    def _sign_challenge(self, challenge: str) -> str:
        """Sign a challenge with the private key"""
        private_key = self._load_private_key()
        
        # Sign the challenge
        signature = private_key.sign(
            challenge.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Return base64-encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    def get_challenge(self) -> str:
        """Get a challenge from the server"""
        # Create SSH tunnel if needed
        tunnel_port = self._create_ssh_tunnel()
        
        # Use tunnel URL if available, otherwise use original URL
        if tunnel_port:
            url = f"http://localhost:{tunnel_port}/auth/challenge"
            if self.config.ssh_verbose:
                print(f"DEBUG: Using SSH tunnel URL: {url}")
        else:
            url = f"{self.config.server_url}/auth/challenge"
            if self.config.ssh_verbose:
                print(f"DEBUG: Using direct URL: {url}")
        
        data = {"hostname": self.config.hostname}
        
        if self.config.ssh_verbose:
            print(f"DEBUG: Requesting challenge from: {url}")
            print(f"DEBUG: Request data: {data}")
        
        try:
            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()
            challenge = response.json()["challenge"]
            if self.config.ssh_verbose:
                print(f"DEBUG: Received challenge: {challenge[:16]}...")
            return challenge
        except requests.exceptions.RequestException as e:
            if self.config.ssh_verbose:
                print(f"DEBUG: Challenge request failed: {e}")
            raise Exception(f"Failed to get challenge: {e}")
    
    def send_sms(self, message: str, to_number: Optional[str] = None) -> Dict:
        """Send an SMS message with authentication"""
        # Get challenge
        challenge = self.get_challenge()
        
        # Sign the challenge
        signature = self._sign_challenge(challenge)
        
        # Prepare SMS data
        sms_data = {
            "message": message,
            "hostname": self.config.hostname,
            "challenge": challenge,
            "signature": signature
        }
        
        # Add recipient if specified
        recipient = to_number or self.config.to_number
        if recipient:
            sms_data["to"] = recipient
        
        # Send SMS
        # Use tunnel URL if available, otherwise use original URL
        tunnel_port = self._create_ssh_tunnel()
        if tunnel_port:
            url = f"http://localhost:{tunnel_port}/sms/send"
            if self.config.ssh_verbose:
                print(f"DEBUG: Using SSH tunnel URL for SMS: {url}")
        else:
            url = f"{self.config.server_url}/sms/send"
            if self.config.ssh_verbose:
                print(f"DEBUG: Using direct URL for SMS: {url}")
        
        if self.config.ssh_verbose:
            print(f"DEBUG: Sending SMS to: {url}")
            print(f"DEBUG: SMS data: {sms_data}")
        
        try:
            response = requests.post(url, json=sms_data, timeout=30)
            response.raise_for_status()
            result = response.json()
            if self.config.ssh_verbose:
                print(f"DEBUG: SMS sent successfully: {result}")
            return result
        except requests.exceptions.RequestException as e:
            if self.config.ssh_verbose:
                print(f"DEBUG: SMS send failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    raise Exception(f"SMS send failed: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
            raise Exception(f"Failed to send SMS: {e}")


def parse_endpoint_info(config_path: str) -> SMSAPIConfig:
    """
    Reads a config to get the correct server URL, hostname, and cryptographic key
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        SMSAPIConfig: Configuration object
    """
    return SMSAPIConfig(config_path)


def post_auth_challenge(api_config: SMSAPIConfig) -> str:
    """
    Get an authentication challenge from the server
    
    Args:
        api_config: SMS API configuration
        
    Returns:
        str: The challenge string
    """
    client = SMSAPIClient(api_config)
    return client.get_challenge()


def send_sms(api_config: SMSAPIConfig, message: str, to_number: Optional[str] = None) -> Dict:
    """
    Send an SMS message with authentication
    
    Args:
        api_config: SMS API configuration
        message: The message to send
        to_number: Optional recipient phone number
        
    Returns:
        Dict: Response from the server
    """
    client = SMSAPIClient(api_config)
    return client.send_sms(message, to_number)
