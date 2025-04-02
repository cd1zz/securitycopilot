import logging
from email.utils import parseaddr, parsedate_to_datetime
import re

logger = logging.getLogger(__name__)

def extract_headers(msg):
    """
    Extract headers from an email message object.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Dictionary containing parsed header information
    """
    logger.debug("Extracting headers from email message")
    
    headers = {
        "message_id": "",
        "sender": "",
        "return_path": "",
        "receiver": "",
        "reply_to": "",
        "subject": "",
        "date": "",
        "smtp": {
            "delivered_to": "",
            "received": []
        },
        "dkim_result": "",
        "spf_result": "",
        "dmarc_result": ""
    }
    
    try:
        # Extract Message-ID
        headers["message_id"] = msg.get("Message-ID", "")
        logger.debug(f"Extracted Message-ID: {headers['message_id']}")
        
        # Extract sender information
        from_header = msg.get("From", "")
        headers["sender"] = from_header
        logger.debug(f"Extracted sender: {headers['sender']}")
        
        # Extract Return-Path
        return_path = msg.get("Return-Path", "")
        if return_path:
            # Remove angle brackets if present
            return_path = re.sub(r'[<>]', '', return_path)
        headers["return_path"] = return_path
        logger.debug(f"Extracted Return-Path: {headers['return_path']}")
        
        # Extract receiver information
        to_header = msg.get("To", "")
        headers["receiver"] = to_header
        logger.debug(f"Extracted receiver: {headers['receiver']}")
        
        # Extract Reply-To
        headers["reply_to"] = msg.get("Reply-To", "")
        logger.debug(f"Extracted Reply-To: {headers['reply_to']}")
        
        # Extract subject
        headers["subject"] = msg.get("Subject", "")
        logger.debug(f"Extracted subject: {headers['subject']}")
        
        # Extract date
        date_header = msg.get("Date", "")
        if date_header:
            try:
                # Try to parse the date into a standard format
                dt = parsedate_to_datetime(date_header)
                headers["date"] = dt.isoformat()
            except Exception as e:
                logger.warning(f"Failed to parse date header: {date_header}, error: {str(e)}")
                headers["date"] = date_header
        logger.debug(f"Extracted date: {headers['date']}")
        
        # Extract SMTP headers
        delivered_to = msg.get("Delivered-To", "")
        headers["smtp"]["delivered_to"] = delivered_to
        
        # Extract all Received headers
        received_headers = msg.get_all("Received", [])
        headers["smtp"]["received"] = received_headers
        logger.debug(f"Extracted {len(received_headers)} Received headers")
        
        # Extract authentication results
        auth_results = msg.get("Authentication-Results", "")
        
        # Extract DKIM result
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            headers["dkim_result"] = dkim_match.group(1)
        
        # Extract SPF result
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            headers["spf_result"] = spf_match.group(1)
        
        # Extract DMARC result
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            headers["dmarc_result"] = dmarc_match.group(1)
        
        logger.debug(f"Extracted authentication results - DKIM: {headers['dkim_result']}, SPF: {headers['spf_result']}, DMARC: {headers['dmarc_result']}")
        
    except Exception as e:
        logger.error(f"Error extracting headers: {str(e)}")
    
    return headers