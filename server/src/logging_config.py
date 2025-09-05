"""
Logging configuration for SMS Notifier

This module provides centralized logging configuration for the SMS Notifier server.
It sets up structured logging with appropriate levels and formats for production use.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime


def setup_logging(log_level=None, log_file=None, max_bytes=10*1024*1024, backup_count=5):
    """
    Set up logging configuration for the SMS Notifier server.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, logs to stdout)
        max_bytes: Maximum size of log file before rotation (default 10MB)
        backup_count: Number of backup log files to keep (default 5)
    """
    
    # Default log level from environment or INFO
    if log_level is None:
        log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    
    # Default log file from environment
    if log_file is None:
        log_file = os.environ.get('LOG_FILE')
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Set up handler
    if log_file:
        # File handler with rotation
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
    else:
        # Console handler
        handler = logging.StreamHandler(sys.stdout)
    
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized - Level: {log_level}, Output: {log_file or 'stdout'}")
    
    return logger


def get_logger(name):
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Security event logging
def log_security_event(event_type, details, client_ip=None, hostname=None):
    """
    Log security-related events with structured information.
    
    Args:
        event_type: Type of security event (e.g., 'auth_failure', 'unauthorized_access')
        details: Additional details about the event
        client_ip: Client IP address
        hostname: Client hostname
    """
    logger = logging.getLogger('security')
    
    # Create structured log message
    log_data = {
        'event_type': event_type,
        'details': details,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    if client_ip:
        log_data['client_ip'] = client_ip
    if hostname:
        log_data['hostname'] = hostname
    
    # Format as key=value pairs for easy parsing
    log_message = ' '.join([f"{k}={v}" for k, v in log_data.items()])
    
    logger.warning(f"SECURITY: {log_message}")


# SMS event logging
def log_sms_event(event_type, message_id=None, to_number=None, from_number=None, 
                  hostname=None, client_ip=None, success=True, error=None):
    """
    Log SMS-related events with structured information.
    
    Args:
        event_type: Type of SMS event (e.g., 'sms_sent', 'sms_failed')
        message_id: Twilio message ID
        to_number: Recipient phone number
        from_number: Sender phone number
        hostname: Client hostname
        client_ip: Client IP address
        success: Whether the operation was successful
        error: Error message if applicable
    """
    logger = logging.getLogger('sms')
    
    # Create structured log message
    log_data = {
        'event_type': event_type,
        'success': success,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    if message_id:
        log_data['message_id'] = message_id
    if to_number:
        log_data['to_number'] = to_number
    if from_number:
        log_data['from_number'] = from_number
    if hostname:
        log_data['hostname'] = hostname
    if client_ip:
        log_data['client_ip'] = client_ip
    if error:
        log_data['error'] = error
    
    # Format as key=value pairs for easy parsing
    log_message = ' '.join([f"{k}={v}" for k, v in log_data.items()])
    
    if success:
        logger.info(f"SMS: {log_message}")
    else:
        logger.error(f"SMS: {log_message}")