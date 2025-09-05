"""
Authentication Blueprint for SMS Notifier

written in part with agentic coding tools (e.g. claude code)

This blueprint provides public key challenge-based authentication endpoints.

To register this blueprint in your Flask app:
    from blueprints.auth import auth_bp
    app.register_blueprint(auth_bp)

Endpoints:
    POST /auth/challenge - Issue a challenge for a hostname
    POST /auth/verify - Verify a challenge response with signature
"""

from flask import Blueprint, request, jsonify
import threading
import logging
import os
from datetime import datetime
from src.challenge import (
    init_db, issue_challenge, verify_challenge_response, 
    get_challenge_for_hostname, clean_expired_challenges,
    load_authorized_keys
)

# Set up logger for this module
logger = logging.getLogger(__name__)

# Create the auth blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Initialize database when blueprint is registered
@auth_bp.before_app_request
def initialize_auth():
    """Initialize the authentication database"""
    # Only initialize once
    if not hasattr(initialize_auth, '_initialized'):
        logger.info("Initializing authentication database")
        init_db()
        logger.info("Authentication database initialized successfully")
        initialize_auth._initialized = True

# Thread-local storage for authorized keys to avoid reloading on every request
_local = threading.local()
_refresh_lock = threading.Lock()
_last_mtime = None

def get_authorized_keys():
    """Get authorized keys, checking file modification time for updates"""
    global _last_mtime
    
    # Get the path to the authorized keys file from the challenge module
    from src.challenge import AUTHORIZED_KEYS_PATH
    
    try:
        current_mtime = os.path.getmtime(AUTHORIZED_KEYS_PATH)
    except (OSError, IOError):
        # If file doesn't exist or can't be accessed, use cached keys if available
        if hasattr(_local, 'authorized_keys'):
            return _local.authorized_keys
        else:
            logger.error(f"Authorized keys file not found: {AUTHORIZED_KEYS_PATH}")
            return {}
    
    # Check if we need to reload (first time or file changed)
    need_reload = False
    with _refresh_lock:
        if _last_mtime is None or current_mtime > _last_mtime:
            _last_mtime = current_mtime
            need_reload = True
    
    if need_reload or not hasattr(_local, 'authorized_keys'):
        logger.debug("Loading/reloading authorized keys for thread")
        _local.authorized_keys = load_authorized_keys()
        logger.info(f"Loaded {len(_local.authorized_keys)} authorized keys")
    
    return _local.authorized_keys

@auth_bp.route("/challenge", methods=["POST"])
def get_challenge():
    """Issue a challenge for a given hostname"""
    client_ip = request.remote_addr
    try:
        data = request.get_json()
        if not data or 'hostname' not in data:
            logger.warning(f"Challenge request missing hostname from {client_ip}")
            return jsonify({"error": "hostname is required"}), 400
        
        hostname = data['hostname']
        logger.info(f"Challenge request for hostname '{hostname}' from {client_ip}")
        
        authorized_keys = get_authorized_keys()
        
        # Check if hostname is authorized
        if hostname not in authorized_keys:
            logger.warning(f"Unauthorized challenge request for hostname '{hostname}' from {client_ip}")
            return jsonify({"error": "Unknown client"}), 401
        
        # Issue challenge
        challenge = issue_challenge(hostname)
        logger.info(f"Challenge issued for hostname '{hostname}' from {client_ip}")
        return jsonify({"challenge": challenge})
        
    except Exception as e:
        logger.error(f"Error issuing challenge from {client_ip}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route("/verify", methods=["POST"])
def verify_challenge():
    """Verify a challenge response"""
    client_ip = request.remote_addr
    try:
        data = request.get_json()
        if not data or not all(key in data for key in ['hostname', 'challenge', 'signature']):
            logger.warning(f"Verify request missing required fields from {client_ip}")
            return jsonify({"error": "hostname, challenge, and signature are required"}), 400
        
        hostname = data['hostname']
        challenge = data['challenge']
        signature = data['signature']
        
        logger.info(f"Verification attempt for hostname '{hostname}' from {client_ip}")
        
        # Get the specific public key for this hostname (from cached authorized keys)
        authorized_keys = get_authorized_keys()
        if hostname not in authorized_keys:
            logger.warning(f"Verification attempt for unauthorized hostname '{hostname}' from {client_ip}")
            return jsonify({"error": "Unknown client"}), 401
        
        public_key = authorized_keys[hostname]
        
        # Verify the challenge response with the specific public key
        if verify_challenge_response(hostname, challenge, signature, public_key):
            logger.info(f"Authentication successful for hostname '{hostname}' from {client_ip}")
            # Clean up expired challenges periodically
            clean_expired_challenges()
            return jsonify({"status": "success", "message": "Authentication successful"})
        else:
            logger.warning(f"Authentication failed for hostname '{hostname}' from {client_ip} - invalid signature")
            return jsonify({"error": "Authentication failed"}), 401
            
    except Exception as e:
        logger.error(f"Error verifying challenge from {client_ip}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
