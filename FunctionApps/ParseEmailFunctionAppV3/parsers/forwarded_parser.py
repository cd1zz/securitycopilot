import logging
import re
import email
from extractors.header_extractor import extract_headers
from extractors.body_extractor import extract_body
from extractors.url_extractor import extract_urls
from extractors.ip_extractor import extract_ip_addresses

def parse_forwarded_email(msg, depth, max_depth, container_path):
    """
    Parse forwarded email content, identifying the original email from various
    email client forwarding formats.
    
    Args:
        msg (email.message.Message): Email message object
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Parsed forwarded email data
    """
    logging.debug(f"Parsing forwarded email at depth {depth}")
    
    # Extract body content
    body = extract_body(msg)
    body_text = body['plain'] + body['html']
    
    # Initialize result
    forwarded_data = {
        "client_type": "unknown",
        "original_sender": "",
        "original_recipient": "",
        "original_subject": "",
        "original_date": "",
        "original_body": "",
        "is_original_phishing_email": False,
        "urls": [],
        "ip_addresses": []
    }
    
    # Try different email client forwarding patterns
    
    # Gmail forwarding pattern
    if "---------- Forwarded message ---------" in body_text:
        logging.debug("Detected Gmail forwarding pattern")
        forwarded_data["client_type"] = "gmail"
        forwarded_data = parse_gmail_forwarded(body_text, forwarded_data)
    
    # Apple Mail forwarding pattern
    elif "Begin forwarded message:" in body_text:
        logging.debug("Detected Apple Mail forwarding pattern")
        forwarded_data["client_type"] = "apple_mail"
        forwarded_data = parse_apple_mail_forwarded(body_text, forwarded_data)
    
    # Outlook forwarding pattern
    elif re.search(r"From:.+?Sent:.+?To:.+?Subject:", body_text, re.DOTALL | re.IGNORECASE):
        logging.debug("Detected Outlook forwarding pattern")
        forwarded_data["client_type"] = "outlook"
        forwarded_data = parse_outlook_forwarded(body_text, forwarded_data)
    
    # Generic forwarding pattern
    elif "-----Original Message-----" in body_text:
        logging.debug("Detected generic forwarding pattern")
        forwarded_data["client_type"] = "generic"
        forwarded_data = parse_generic_forwarded(body_text, forwarded_data)
    
    # Extract URLs and IP addresses from the original body
    if forwarded_data["original_body"]:
        forwarded_data["urls"] = extract_urls(forwarded_data["original_body"])
        forwarded_data["ip_addresses"] = extract_ip_addresses(forwarded_data["original_body"])
    
    return forwarded_data

def parse_gmail_forwarded(body_text, forwarded_data):
    """
    Parse Gmail-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logging.debug("Parsing Gmail forwarded email")
    
    try:
        # Extract header section after the forwarded message marker
        gmail_pattern = r"---------- Forwarded message ---------\s*\n(.*?)(?:\n\n|\Z)"
        header_match = re.search(gmail_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"---------- Forwarded message ---------\s*\n.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logging.error(f"Error parsing Gmail forwarded email: {str(e)}")
    
    return forwarded_data

def parse_apple_mail_forwarded(body_text, forwarded_data):
    """
    Parse Apple Mail-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logging.debug("Parsing Apple Mail forwarded email")
    
    try:
        # Extract header section after the forwarded message marker
        apple_pattern = r"Begin forwarded message:(.*?)(?:\n\n|\Z)"
        header_match = re.search(apple_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"Begin forwarded message:.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logging.error(f"Error parsing Apple Mail forwarded email: {str(e)}")
    
    return forwarded_data

def parse_outlook_forwarded(body_text, forwarded_data):
    """
    Parse Outlook-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logging.debug("Parsing Outlook forwarded email")
    
    try:
        # Extract the entire header block
        outlook_pattern = r"(From:.+?Sent:.+?To:.+?Subject:.+?)(?:\n\n|\Z)"
        header_match = re.search(outlook_pattern, body_text, re.DOTALL | re.IGNORECASE)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Sent (Date)
            date_match = re.search(r"Sent:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        header_end_index = body_text.find(header_match.group(0)) + len(header_match.group(0)) if header_match else -1
        
        if header_end_index > 0 and header_end_index < len(body_text):
            forwarded_data["original_body"] = body_text[header_end_index:].strip()
        
    except Exception as e:
        logging.error(f"Error parsing Outlook forwarded email: {str(e)}")
    
    return forwarded_data

def parse_generic_forwarded(body_text, forwarded_data):
    """
    Parse generic forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logging.debug("Parsing generic forwarded email")
    
    try:
        # Extract header section
        generic_pattern = r"-----Original Message-----(.*?)(?:\n\n|\Z)"
        header_match = re.search(generic_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section) or \
                         re.search(r"Sent:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"-----Original Message-----.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logging.error(f"Error parsing generic forwarded email: {str(e)}")
    
    return forwarded_data