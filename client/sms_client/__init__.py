"""
SMS Notifier Client

A Python client library for the SMS Notifier API with public key authentication.
"""

from .sms_api_caller import SMSAPIConfig, SMSAPIClient, send_sms, post_auth_challenge, parse_endpoint_info

__all__ = [
    'SMSAPIConfig',
    'SMSAPIClient', 
    'send_sms',
    'post_auth_challenge',
    'parse_endpoint_info'
]

__version__ = "0.1.0"

