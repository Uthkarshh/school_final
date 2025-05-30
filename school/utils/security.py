"""Security utility functions."""

import logging
import re
import secrets
import string
from typing import Tuple

from flask import session
from markupsafe import Markup, escape

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 10  # Minimum password length


def generate_csrf_token() -> str:
    """Generate a secure CSRF token.
    
    Returns:
        Secure CSRF token string
    """
    token = secrets.token_hex(32)
    session['_csrf_token'] = token
    return token


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength against security requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common passwords - simplified version
    common_passwords = ['password', 'admin123', '123456', 'qwerty', 'welcome']
    if password.lower() in common_passwords:
        return False, "Password is too common and easily guessable"
    
    return True, ""


def sanitize_html(value: str) -> str:
    """Sanitize HTML content to prevent XSS.
    
    Args:
        value: String to sanitize
        
    Returns:
        Sanitized string
    """
    if not value:
        return ""
    
    # First use Markup.escape to escape all HTML
    escaped = escape(value)
    
    # Remove potentially dangerous patterns
    dangerous_patterns = [
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'on\w+\s*=',
        r'<script',
        r'<iframe',
        r'<object',
        r'<embed'
    ]
    
    result = str(escaped)
    for pattern in dangerous_patterns:
        result = re.sub(pattern, '', result, flags=re.IGNORECASE)
    
    return result.strip()
