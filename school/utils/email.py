"""Email utility functions."""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Union

logger = logging.getLogger(__name__)

SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@example.com')
EMAIL_ENABLED = os.environ.get('EMAIL_ENABLED', 'False').lower() == 'true'


def send_email(recipient: Union[str, List[str]], subject: str, body: str, html_body: str = None) -> bool:
    """Send an email to one or more recipients.
    
    Args:
        recipient: Email address or list of email addresses
        subject: Email subject
        body: Plain text email body
        html_body: Optional HTML email body
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    if not EMAIL_ENABLED:
        logger.info(f"Email sending is disabled. Would have sent email to {recipient} with subject '{subject}'")
        return True
        
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        logger.error("SMTP credentials not configured")
        return False
        
    # Convert single recipient to list
    recipients = [recipient] if isinstance(recipient, str) else recipient
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = DEFAULT_FROM_EMAIL
        msg['To'] = ', '.join(recipients)
        
        # Attach parts
        msg.attach(MIMEText(body, 'plain'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))
        
        # Connect to server and send
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            
        logger.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False
