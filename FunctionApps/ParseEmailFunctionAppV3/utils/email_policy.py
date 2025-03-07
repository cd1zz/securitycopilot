# utils/email_policy.py
import logging
from email.policy import EmailPolicy

logger = logging.getLogger(__name__)

class CustomEmailPolicy(EmailPolicy):
    """
    Custom email policy to handle common email parsing issues like 
    malformed Message-ID headers with square brackets.
    """
    def header_fetch_parse(self, name, value):
        if name == 'Message-ID':
            if isinstance(value, str) and ('[' in value or ']' in value):
                # Strip square brackets from Message-ID
                clean_value = value.replace('[', '').replace(']', '')
                logger.debug(f"Cleaned Message-ID: {clean_value}")
                return clean_value
        return super().header_fetch_parse(name=name, value=value)