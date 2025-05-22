"""
Logging utilities for the school fee management application.

This module configures structured logging with various handlers and provides
utility functions for consistent logging across the application.
"""

import functools
import inspect
import json
import logging
import logging.handlers
import os
import re
import sys
import time
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union, cast

from flask import Request, has_request_context, request

# Environment configuration
ENV = os.getenv("FLASK_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG" if ENV == "development" else "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "json" if ENV == "production" else "text")
LOG_DIR = os.getenv("LOG_DIR", "logs")

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure log file paths
APP_LOG_FILE = os.path.join(LOG_DIR, "app.log")
ERROR_LOG_FILE = os.path.join(LOG_DIR, "error.log")
REQUEST_LOG_FILE = os.path.join(LOG_DIR, "requests.log")
SECURITY_LOG_FILE = os.path.join(LOG_DIR, "security.log")


# Regular expressions for sanitizing sensitive data
SENSITIVE_PATTERNS = [
    (re.compile(r"\b\d{12}\b"), "XXXX-XXXX-XXXX"),  # Aadhar numbers
    (re.compile(r"\b(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b"), "EMAIL-REDACTED"),  # Email addresses
    (re.compile(r"\b(?:\+\d{1,3}[\s-])?\d{10}\b"), "PHONE-REDACTED"),  # Phone numbers
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password":"REDACTED"'),  # Passwords in JSON
    (re.compile(r"password=([^&]*)"), "password=REDACTED"),  # Passwords in query strings
]


class RequestFormatter(logging.Formatter):
    """Custom formatter that includes request information when available."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with request details when in request context.
        
        Args:
            record: The log record to format
            
        Returns:
            Formatted log string
        """
        # Add request info if available
        if has_request_context():
            record.url = request.url
            record.remote_addr = request.remote_addr
            record.method = request.method
            record.endpoint = request.endpoint
            
            # Include user info if authenticated
            if hasattr(request, "user") and request.user and hasattr(request.user, "id"):
                record.user_id = request.user.id
                record.username = request.user.username
            else:
                record.user_id = "anonymous"
                record.username = "anonymous"
        else:
            record.url = None
            record.remote_addr = None
            record.method = None
            record.endpoint = None
            record.user_id = None
            record.username = None
            
        # Call the parent formatter
        return super().format(record)


class JsonFormatter(RequestFormatter):
    """JSON formatter for structured logging."""

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        """Initialize with optional format strings.
        
        Args:
            fmt: Format string (ignored for JSON)
            datefmt: Date format string
        """
        super().__init__(fmt, datefmt)
        self.datefmt = datefmt or "%Y-%m-%dT%H:%M:%S.%fZ"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: The log record to format
            
        Returns:
            JSON-formatted log string
        """
        # Process the record with the parent formatter first to add request context
        super().format(record)
        
        # Create JSON log object
        log_dict = {
            "timestamp": datetime.fromtimestamp(record.created).strftime(self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.thread,
        }
        
        # Add request info if available
        if hasattr(record, "url") and record.url is not None:
            log_dict["request"] = {
                "url": record.url,
                "method": record.method,
                "endpoint": record.endpoint,
                "ip": record.remote_addr,
                "user_id": record.user_id,
                "username": record.username,
            }
            
        # Add exception info if available
        if record.exc_info:
            log_dict["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }
            
        # Add custom fields
        for key, value in record.__dict__.items():
            if key not in [
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "id", "levelname", "levelno", "lineno", "module",
                "msecs", "message", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread", "threadName",
                "url", "remote_addr", "method", "endpoint", "user_id", "username"
            ] and not key.startswith("_"):
                log_dict[key] = value
                
        # Sanitize sensitive data
        log_json = json.dumps(log_dict)
        sanitized_log = sanitize_log_message(log_json)
        
        return sanitized_log


def sanitize_log_message(message: str) -> str:
    """Sanitize log messages to remove sensitive information.
    
    Args:
        message: The log message to sanitize
        
    Returns:
        Sanitized log message
    """
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def configure_logging() -> None:
    """Configure the logging system for the application."""
    # Determine log level
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    
    # Create formatters
    if LOG_FORMAT.lower() == "json":
        formatter = JsonFormatter()
    else:
        formatter = RequestFormatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(url)s - %(remote_addr)s]",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)
    
    # Application log file handler with rotation
    app_handler = logging.handlers.RotatingFileHandler(
        APP_LOG_FILE, maxBytes=10485760, backupCount=5
    )
    app_handler.setFormatter(formatter)
    app_handler.setLevel(log_level)
    root_logger.addHandler(app_handler)
    
    # Error log file handler with rotation (ERROR and above)
    error_handler = logging.handlers.RotatingFileHandler(
        ERROR_LOG_FILE, maxBytes=10485760, backupCount=10
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)
    
    # Create specialized loggers
    
    # Request logger
    request_logger = logging.getLogger("request")
    request_handler = logging.handlers.RotatingFileHandler(
        REQUEST_LOG_FILE, maxBytes=10485760, backupCount=5
    )
    request_handler.setFormatter(formatter)
    request_logger.addHandler(request_handler)
    request_logger.propagate = False
    
    # Security logger
    security_logger = logging.getLogger("security")
    security_handler = logging.handlers.RotatingFileHandler(
        SECURITY_LOG_FILE, maxBytes=10485760, backupCount=20
    )
    security_handler.setFormatter(formatter)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    # Set up logging for library loggers - limit verbosity
    for lib_logger in ["werkzeug", "sqlalchemy", "flask_sqlalchemy", "urllib3"]:
        logging.getLogger(lib_logger).setLevel(logging.WARNING)


def log_exception(exception: Exception, message: str = None) -> None:
    """Log an exception with enhanced details.
    
    Args:
        exception: The exception to log
        message: Optional message to include
    """
    logger = logging.getLogger()
    
    # Get the caller's frame information
    caller_frame = inspect.currentframe().f_back
    filename = caller_frame.f_code.co_filename
    lineno = caller_frame.f_lineno
    function = caller_frame.f_code.co_name
    
    # Create detailed error message
    error_msg = f"{message or 'Exception occurred'}: {str(exception)}"
    logger.error(
        f"{error_msg} [in {os.path.basename(filename)}:{lineno} - {function}()]", 
        exc_info=exception
    )


def log_security_event(event_type: str, details: Dict[str, Any], severity: str = "WARNING") -> None:
    """Log security-related events to the security log.
    
    Args:
        event_type: Type of security event (login_failure, permission_denied, etc.)
        details: Dictionary of event details
        severity: Log level for the event (INFO, WARNING, ERROR)
    """
    security_logger = logging.getLogger("security")
    log_level = getattr(logging, severity.upper(), logging.WARNING)
    
    # Add timestamp if not present
    if "timestamp" not in details:
        details["timestamp"] = datetime.now().isoformat()
        
    # Construct message
    message = f"Security event: {event_type}"
    
    # Log with appropriate level
    security_logger.log(log_level, message, extra={"security_event": event_type, "details": details})


def log_request(response=None) -> None:
    """Log HTTP request details.
    
    Args:
        response: Optional Flask response object
    """
    if not has_request_context():
        return
        
    request_logger = logging.getLogger("request")
    
    # Extract request details
    details = {
        "method": request.method,
        "url": request.url,
        "endpoint": request.endpoint,
        "ip": request.remote_addr,
        "user_agent": request.user_agent.string if request.user_agent else None,
        "referrer": request.referrer,
    }
    
    # Add response details if available
    if response:
        details["status_code"] = response.status_code
        details["response_length"] = response.content_length
        
    # Log the request
    request_logger.info(f"Request: {request.method} {request.url}", extra=details)


def log_slow_operation(threshold_seconds: float = 1.0) -> Callable:
    """Decorator to log slow operations.
    
    Args:
        threshold_seconds: Time threshold in seconds to consider an operation slow
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed_time = time.time() - start_time
                if elapsed_time > threshold_seconds:
                    logger = logging.getLogger()
                    logger.warning(
                        f"Slow operation: {func.__name__} took {elapsed_time:.2f}s to complete",
                        extra={
                            "operation": func.__name__,
                            "execution_time": elapsed_time,
                            "threshold": threshold_seconds
                        }
                    )
        return wrapper
    return decorator


# Initialize logging when module is imported
configure_logging()
