# utils/__init__.py

"""
Utility module initialization for AdvoShield
Includes: audit logging, crypto tools, and helper functions.
"""

from .audit_logger import AuditLogger
from .crypto import encrypt_data, decrypt_data, hash_file
from .helpers import is_valid_ip, calculate_entropy

__all__ = [
    "log_event",
    "encrypt_data", "decrypt_data", "hash_file",
    "is_valid_ip", "calculate_entropy"
]