import email
import base64
import os
import sys
import logging
import re
from email import policy
from email.parser import BytesParser, Parser

# Assuming these will be implemented
from extractors.header_extractor import extract_headers
from extractors.body_extractor import extract_body
from extractors.attachment_extractor import extract_attachments
from extractors.url_extractor import extract_urls
from extractors.ip_extractor import extract_ip_addresses
from extractors.domain_extractor import extract_domains
from utils.mime_utils import analyze_mime_structure

def parse_email(email_content, depth=0, max_depth=10, container_path=None):
    """
    Main function to parse an email with recursive unwrapping to find original email.
    
    Args:
        email_content (str or bytes): Raw email content
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth to prevent infinite loops
        container_path (list): Path of containers (how this email was contained)
        
    Returns:
        dict: Original email data only, without debug/progress information
    """
    if depth > max_depth:
        return {"error": f"Maximum recursion depth ({max_depth}) exceeded"}
    
    if container_path is None:
        container_path = []
    
    logging.debug(f"Parsing email at depth {depth} with container path {container_path}")
    
    # Initialize result structure - not returned but used internally
    parsed_data = {
        "email_content": {
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
            "dmarc_result": "",
            "body": "",  # Single string body
            "attachments": [],
            "email_depth": depth,
            "container_type": container_path[-1] if container_path else "root"
        },
        "ip_addresses": [],
        "urls": [],
        "domains": []
    }
    
    # Convert to bytes if string is provided
    if isinstance(email_content, str):
        email_content = email_content.encode('utf-8', errors='replace')
    
    # Parse the email content
    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_content)
    except Exception as e:
        logging.error(f"Failed to parse email: {str(e)}")
        return {"error": f"Failed to parse email: {str(e)}"}
    
    # Extract headers
    headers = extract_headers(msg)
    parsed_data["email_content"].update(headers)
    
    # Extract body content - this will now return plain, html, and the combined body
    body_data = extract_body(msg)
    
    # Store only the combined body in the output
    parsed_data["email_content"]["body"] = body_data["body"]
    
    # Extract and process URLs from both plain and HTML parts for analysis
    urls = extract_urls(body_data["plain"] + " " + body_data["html"])
    parsed_data["urls"] = urls
    
    # Extract IP addresses from body and headers
    headers_text = " ".join([f"{k}: {v}" for k, v in msg.items()])
    ip_addresses = extract_ip_addresses(body_data["plain"] + " " + body_data["html"] + " " + headers_text)
    parsed_data["ip_addresses"] = ip_addresses
    
    # Extract domains from URLs
    domains = extract_domains(urls)
    parsed_data["domains"] = domains
    
    # Variable to track if we've found an original email deeper in the structure
    found_original_email = False
    original_email = None
    
    # Check if this is a forwarded email
    if is_forwarded_email(msg, body_data):
        logging.debug("Email is forwarded, parsing forwarded content")
        forwarded_data = parse_forwarded_email(
            msg, 
            depth + 1, 
            max_depth, 
            container_path + ["forwarded"]
        )
        
        # Always extract the forwarded content as the original email
        original_email = extract_original_email(forwarded_data)
        original_email["container_path"] = container_path + ["forwarded"]
        original_email["reconstruction_method"] = "forwarded"
        original_email["urls"] = forwarded_data.get("urls", [])
        original_email["ip_addresses"] = forwarded_data.get("ip_addresses", [])
        original_email["domains"] = extract_domains(forwarded_data.get("urls", []))
        found_original_email = True
    
    # Extract and process attachments, looking for embedded emails
    attachments = extract_attachments(msg, depth, max_depth, container_path)
    # Filter out None values (image attachments will be None)
    attachments = [attachment for attachment in attachments if attachment is not None]
    parsed_data["email_content"]["attachments"] = attachments
    
    # Process any email attachments recursively
    for i, attachment in enumerate(attachments):
        if attachment.get("is_email", False) and "parsed_email" in attachment:
            # If this is the first embedded email found
            if not found_original_email:
                logging.debug(f"Found original email in attachment {i}")
                # Get the original email directly from the parsed attachment
                if isinstance(attachment["parsed_email"], dict) and "original_email" in attachment["parsed_email"]:
                    original_email = attachment["parsed_email"]["original_email"]
                elif isinstance(attachment["parsed_email"], dict) and "email_content" in attachment["parsed_email"]:
                    original_email = extract_original_email(attachment["parsed_email"]["email_content"])
                else:
                    # Skip if we can't extract a proper original email
                    logging.warning(f"Could not extract original email from attachment {i}")
                    continue
                    
                original_email["container_path"] = container_path + [f"attachment[{i}]"]
                original_email["reconstruction_method"] = "attachment"
                
                # Add URLs, IPs, and domains if available
                if isinstance(attachment["parsed_email"], dict):
                    original_email["urls"] = attachment["parsed_email"].get("urls", [])
                    original_email["ip_addresses"] = attachment["parsed_email"].get("ip_addresses", [])
                    original_email["domains"] = attachment["parsed_email"].get("domains", 
                                               extract_domains(attachment["parsed_email"].get("urls", [])))
                    
                found_original_email = True
    
    # Handle multipart MIME structure
    if msg.is_multipart():
        mime_analysis = analyze_mime_structure(msg)
        
        # Check for embedded emails in MIME parts that aren't formal attachments
        for part_index, part in enumerate(mime_analysis["reconstructed_parts"]):
            if is_embedded_email(part["content"]):
                logging.debug(f"Found potential embedded email in MIME part {part_index}")
                embedded_email = parse_email(
                    part["content"], 
                    depth + 1, 
                    max_depth,
                    container_path + [f"mime_part[{part_index}]"]
                )
                
                # If we found an original email in the embedded content
                if isinstance(embedded_email, dict) and "original_email" in embedded_email and not found_original_email:
                    logging.debug(f"Using original email from MIME part {part_index}")
                    original_email = embedded_email["original_email"]
                    original_email["container_path"] = container_path + [f"mime_part[{part_index}]"]
                    original_email["reconstruction_method"] = "mime_embedded"
                    found_original_email = True
    
    # If we haven't found an original email deeper in the structure,
    # use the current email as the original
    if not found_original_email:
        logging.debug("Using current email as the original")
        original_email = extract_original_email(parsed_data["email_content"])
        original_email["container_path"] = container_path
        original_email["reconstruction_method"] = "direct"
        original_email["urls"] = parsed_data["urls"]
        original_email["ip_addresses"] = parsed_data["ip_addresses"]
        original_email["domains"] = parsed_data["domains"]
    
    # Return just the original email data, not the full parsed data
    return {"original_email": original_email}

def is_forwarded_email(msg, body_data=None):
    """
    Check if the email is a forwarded email based on various indicators.
    
    Args:
        msg (email.message.Message): Email message object
        body_data (dict, optional): Body data if already extracted
        
    Returns:
        bool: True if it's a forwarded email, False otherwise
    """
    # Check subject for forwarding indicators
    subject = msg.get('Subject', '')
    if subject.lower().startswith(('fw:', 'fwd:')):
        return True
    
    # Check content for forwarding patterns
    if body_data is None:
        # If body_data wasn't provided, extract it now
        body_data = extract_body(msg)
    
    # Use both plain and HTML for checking patterns
    body_text = ""
    if isinstance(body_data, dict):
        if "plain" in body_data and "html" in body_data:
            body_text = body_data["plain"] + " " + body_data["html"]
        elif "body" in body_data:
            body_text = body_data["body"]
    else:
        # Fallback if body_data is not a dict
        body_text = str(body_data)
    
    # Common forwarding patterns from different email clients
    forwarding_patterns = [
        "---------- Forwarded message ---------",  # Gmail
        "Begin forwarded message:",              # Apple Mail
        "From: .* Sent: .* To: .* Subject:",    # Outlook
        "-----Original Message-----",           # Various clients
        "Forwarded Message",                    # Various clients
    ]
    
    for pattern in forwarding_patterns:
        if pattern.lower() in body_text.lower():
            return True
    
    return False

def parse_forwarded_email(msg, depth, max_depth, container_path):
    """
    Parse forwarded email content.
    
    Args:
        msg (email.message.Message): Email message object
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Parsed forwarded email data
    """
    # This would be implemented in forwarded_parser.py
    # Import here to avoid circular import
    from parsers.forwarded_parser import parse_forwarded_email as parse_forwarded
    
    # Call the actual implementation
    return parse_forwarded(msg, depth, max_depth, container_path)

def is_embedded_email(content):
    """
    Check if content is an embedded email.
    
    Args:
        content (str or bytes): Content to check
        
    Returns:
        bool: True if it's an embedded email, False otherwise
    """
    # Simple check for email patterns
    if isinstance(content, bytes):
        try:
            content = content.decode('utf-8', errors='replace')
        except:
            return False
    
    # Check for email headers
    header_patterns = [
        r"From:.*\n",
        r"To:.*\n",
        r"Subject:.*\n",
        r"Date:.*\n",
        r"Message-ID:.*\n"
    ]
    
    header_count = 0
    for pattern in header_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            header_count += 1
    
    # If we find at least 3 header patterns, it's likely an embedded email
    return header_count >= 3

def extract_original_email(email_data):
    """
    Extract the original email from parsed data.
    
    Args:
        email_data (dict): Parsed email data
        
    Returns:
        dict: Original email data
    """
    original_email = {
        "message_id": "",
        "sender": "",
        "return_path": "",
        "receiver": "",
        "reply_to": "",
        "subject": "",
        "date": "",
        "body": "",  
        "attachments": [],
        "container_path": [],
        "reconstruction_method": ""
    }
    
    # Copy relevant fields from email_data
    if "message_id" in email_data:
        original_email["message_id"] = email_data["message_id"]
    if "sender" in email_data:
        original_email["sender"] = email_data["sender"]
    if "return_path" in email_data:
        original_email["return_path"] = email_data["return_path"]
    if "receiver" in email_data:
        original_email["receiver"] = email_data["receiver"]
    if "reply_to" in email_data:
        original_email["reply_to"] = email_data["reply_to"]
    if "subject" in email_data:
        original_email["subject"] = email_data["subject"]
    if "date" in email_data:
        original_email["date"] = email_data["date"]
    if "body" in email_data:
        # Handle both string and dict formats for backwards compatibility
        if isinstance(email_data["body"], dict):
            if "body" in email_data["body"]:
                original_email["body"] = email_data["body"]["body"]
            elif "plain" in email_data["body"]:
                # Fallback to plain text if available
                original_email["body"] = email_data["body"]["plain"]
            elif "html" in email_data["body"]:
                # Fallback to HTML with tags removed
                html_body = email_data["body"]["html"]
                plain_body = re.sub(r'<[^>]+>', ' ', html_body)
                plain_body = re.sub(r'\s+', ' ', plain_body).strip()
                original_email["body"] = plain_body
        else:
            # If it's already a string
            original_email["body"] = email_data["body"]
    if "attachments" in email_data:
        original_email["attachments"] = email_data["attachments"]
    
    return original_email