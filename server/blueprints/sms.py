"""
SMS Blueprint for SMS Notifier

written with cursor agent

This blueprint provides SMS sending functionality with built-in authentication.

To register this blueprint in your Flask app:
    from blueprints.sms import sms_bp
    app.register_blueprint(sms_bp)

Endpoints:
    POST /sms/send - Send SMS message with challenge response authentication

Usage Flow:
    1. POST /auth/challenge with hostname to get challenge
    2. Sign the challenge with your private key
    3. POST /sms/send with message, hostname, challenge, and signature
"""

import os
import threading
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from twilio.rest import Client
from twilio.base.exceptions import TwilioException
from src.challenge import load_authorized_keys, verify_challenge_response

# Set up logger for this module
logger = logging.getLogger(__name__)

# Create the SMS blueprint
sms_bp = Blueprint('sms', __name__, url_prefix='/sms')

# Thread-local storage for Twilio client and authorized keys
_local = threading.local()

def get_twilio_client():
    """Get Twilio client, creating it once per thread"""
    if not hasattr(_local, 'twilio_client'):
        # Check if we're in debug mode
        debug_mode = os.environ.get("SMS_DEBUG_MODE", "false").lower() == "true"
        
        if debug_mode:
            logger.debug("Debug mode: Using mock Twilio client")
            _local.twilio_client = None  # Will be handled in send_sms
        else:
            logger.debug("Initializing Twilio client for thread")
            account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
            auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
            _local.twilio_client = Client(account_sid, auth_token)
            logger.info("Twilio client initialized successfully")
    return _local.twilio_client

def get_authorized_keys():
    """Get authorized keys, loading them once per thread"""
    if not hasattr(_local, 'authorized_keys'):
        logger.debug("Loading authorized keys for SMS thread")
        _local.authorized_keys = load_authorized_keys()
        logger.info(f"Loaded {len(_local.authorized_keys)} authorized keys for SMS")
    return _local.authorized_keys

def verify_auth(data):
    """Verify authentication using challenge response"""
    if not all(key in data for key in ['hostname', 'challenge', 'signature']):
        logger.warning("SMS request missing required authentication fields")
        return None, "hostname, challenge, and signature are required"
    
    hostname = data['hostname']
    challenge = data['challenge']
    signature = data['signature']
    
    logger.debug(f"SMS authentication attempt for hostname '{hostname}'")
    
    # Get the specific public key for this hostname
    authorized_keys = get_authorized_keys()
    if hostname not in authorized_keys:
        logger.warning(f"SMS request from unauthorized hostname '{hostname}'")
        return None, "Unauthorized client"
    
    public_key = authorized_keys[hostname]
    
    # Verify the challenge response
    if not verify_challenge_response(hostname, challenge, signature, public_key):
        logger.warning(f"SMS authentication failed for hostname '{hostname}' - invalid signature")
        return None, "Authentication failed"
    
    logger.info(f"SMS authentication successful for hostname '{hostname}'")
    return hostname, None

@sms_bp.route("/send", methods=["POST"])
def send_sms():
    """Send an SMS message with authentication"""
    client_ip = request.remote_addr
    try:
        data = request.get_json()
        if not data:
            logger.warning(f"SMS request with no JSON data from {client_ip}")
            return jsonify({"error": "JSON data required"}), 400
        
        # Verify authentication first
        hostname, auth_error = verify_auth(data)
        if auth_error:
            logger.warning(f"SMS authentication failed from {client_ip}: {auth_error}")
            return jsonify({"error": auth_error}), 401
        
        # Check for required message field
        if 'message' not in data:
            logger.warning(f"SMS request missing message field from {client_ip}")
            return jsonify({"error": "message is required"}), 400
        
        message = data['message']
        to_number = data.get('to', os.environ.get("YOUR_PHONE_NUMBER"))
        
        if not to_number:
            logger.error(f"SMS request missing recipient phone number from {client_ip}")
            return jsonify({"error": "recipient phone number required"}), 400
        
        # Validate message length
        if len(message) > 1600:  # Twilio's limit
            logger.warning(f"SMS message too long ({len(message)} chars) from {client_ip}")
            return jsonify({"error": "message too long (max 1600 characters)"}), 400
        
        logger.info(f"SMS send request from hostname '{hostname}' to {to_number} from {client_ip}")
        
        # Check if we're in debug mode
        debug_mode = os.environ.get("SMS_DEBUG_MODE", "false").lower() == "true"
        
        if debug_mode:
            # Mock SMS sending in debug mode
            mock_message_id = f"debug-{datetime.utcnow().timestamp()}"
            mock_twilio_number = os.environ.get("TWILIO_PHONE_NUMBER", "+0987654321")
            
            logger.info(f"SMS sent successfully (DEBUG MODE) - ID: {mock_message_id}, from: {mock_twilio_number}, to: {to_number}, client: {hostname}")
            logger.info(f"DEBUG: Message content: {message}")
            
            return jsonify({
                "status": "success",
                "message": "SMS sent successfully (debug mode)",
                "message_id": mock_message_id,
                "to": to_number,
                "from": mock_twilio_number,
                "client": hostname,
                "debug": True
            })
        else:
            # Real SMS sending
            client = get_twilio_client()
            twilio_number = os.environ.get("TWILIO_PHONE_NUMBER")
            
            if not twilio_number:
                logger.error("Twilio phone number not configured")
                return jsonify({"error": "Twilio phone number not configured"}), 500
            
            # Send the SMS
            message_obj = client.messages.create(
                body=message,
                from_=twilio_number,
                to=to_number
            )
            
            logger.info(f"SMS sent successfully - ID: {message_obj.sid}, from: {twilio_number}, to: {to_number}, client: {hostname}")
            
            return jsonify({
                "status": "success",
                "message": "SMS sent successfully",
                "message_id": message_obj.sid,
                "to": to_number,
                "from": twilio_number,
                "client": hostname
            })
        
    except TwilioException as e:
        logger.error(f"Twilio error sending SMS from {client_ip}: {str(e)}")
        return jsonify({"error": f"Twilio error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error sending SMS from {client_ip}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
