"""
Example Flask Application showing how to integrate auth and SMS blueprints

This demonstrates the proper separation of concerns:
- auth blueprint handles authentication
- sms blueprint handles SMS sending with auth checks
"""

import os
from flask import Flask, jsonify
from blueprints.auth import auth_bp, initialize_auth
from blueprints.sms import sms_bp
from src.logging_config import setup_logging, get_logger

def create_app():
    """Create and configure the Flask application"""
    # Set up logging first
    setup_logging()
    logger = get_logger(__name__)
    
    logger.info("Creating Flask application")
    
    app = Flask(__name__)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(sms_bp)
    logger.info("Registered auth and SMS blueprints")
    
    # Initialize authentication database
    initialize_auth()
    
    # Simple health check
    @app.route('/health')
    def health_check():
        logger.debug("Health check requested")
        return jsonify({"status": "healthy"})
    
    logger.info("Flask application created successfully")
    return app

if __name__ == '__main__':
    app = create_app()
    logger = get_logger(__name__)
    
    # Get configuration from environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting SMS Notifier server on {host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)