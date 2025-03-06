import email
import base64
import os
import sys
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
    Main function to parse an email with recursive unwrapping to find original phishing email.
    
    Args:
        email_content (str or bytes): Raw email content
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth to prevent infinite loops
        container_path (list): Path of containers (how this email was contained)
        
    Returns:
        dict: Parsed email data in JSON format with original phishing email identified
    """
    if depth > max_depth:
        return {"error": f"Maximum recursion depth ({max_depth}) exceeded"}
    
    if container_path is None:
        container_path = []
    
    # Initialize result structure
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
            "body": {
                "plain": "",
                "html": ""
            },
            "attachments": [],
            "is_original_phishing_email": False,
            "email_depth": depth,
            "container_type": container_path[-1] if container_path else "root"
        },
        "ip_addresses": [],
        "urls": [],
        "domains": [],
        "mime_analysis": {
            "parts_count": 0,
            "boundaries": [],
            "content_types": [],
            "reconstructed_parts": []
        }
    }
    
    # Convert to bytes if string is provided
    if isinstance(email_content, str):
        email_content = email_content.encode('utf-8', errors='replace')
    
    # Parse the email content
    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_content)
    except Exception as e:
        return {"error": f"Failed to parse email: {str(e)}"}
    
    # Extract headers
    headers = extract_headers(msg)
    parsed_data["email_content"].update(headers)
    
    # Extract body content
    body = extract_body(msg)
    parsed_data["email_content"]["body"] = body
    
    # Extract and process URLs from body
    urls = extract_urls(body["plain"] + " " + body["html"])
    parsed_data["urls"] = urls
    
    # Extract IP addresses from body and headers
    headers_text = " ".join([f"{k}: {v}" for k, v in msg.items()])
    ip_addresses = extract_ip_addresses(body["plain"] + " " + body["html"] + " " + headers_text)
    parsed_data["ip_addresses"] = ip_addresses
    
    # Extract domains from URLs
    domains = extract_domains(urls)
    parsed_data["domains"] = domains
    
    # Check if this is a forwarded email
    if is_forwarded_email(msg):
        forwarded_data = parse_forwarded_email(
            msg, 
            depth + 1, 
            max_depth, 
            container_path + ["forwarded"]
        )
        parsed_data["forwarded_content"] = forwarded_data
        
        # If this forwarded content appears to be the original phishing email
        if is_likely_phishing_email(forwarded_data):
            parsed_data["original_phishing_email"] = extract_original_email(forwarded_data)
            parsed_data["original_phishing_email"]["container_path"] = container_path + ["forwarded"]
            parsed_data["original_phishing_email"]["reconstruction_method"] = "forwarded"
    
    # Extract and process attachments, looking for embedded emails
    attachments = extract_attachments(msg, depth, max_depth, container_path)
    parsed_data["email_content"]["attachments"] = attachments
    
    # Process any email attachments recursively
    for i, attachment in enumerate(attachments):
        if attachment.get("is_email", False) and "parsed_email" in attachment:
            # If this attached email appears to be the original phishing email
            if is_likely_phishing_email(attachment["parsed_email"]["email_content"]):
                parsed_data["original_phishing_email"] = extract_original_email(attachment["parsed_email"]["email_content"])
                parsed_data["original_phishing_email"]["container_path"] = container_path + [f"attachment[{i}]"]
                parsed_data["original_phishing_email"]["reconstruction_method"] = "attachment"
    
    # Handle multipart MIME structure
    if msg.is_multipart():
        mime_analysis = analyze_mime_structure(msg)
        parsed_data["mime_analysis"] = mime_analysis
        
        # Check for embedded emails in MIME parts that aren't formal attachments
        for part_index, part in enumerate(mime_analysis["reconstructed_parts"]):
            if is_embedded_email(part["content"]):
                embedded_email = parse_email(
                    part["content"], 
                    depth + 1, 
                    max_depth,
                    container_path + [f"mime_part[{part_index}]"]
                )
                
                # If this embedded content appears to be the original phishing email
                if "email_content" in embedded_email and is_likely_phishing_email(embedded_email["email_content"]):
                    parsed_data["original_phishing_email"] = extract_original_email(embedded_email["email_content"])
                    parsed_data["original_phishing_email"]["container_path"] = container_path + [f"mime_part[{part_index}]"]
                    parsed_data["original_phishing_email"]["reconstruction_method"] = "mime_embedded"
    
    # If we haven't found an original phishing email deeper in the structure,
    # check if the current email might be it
    if "original_phishing_email" not in parsed_data and is_likely_phishing_email(parsed_data["email_content"]):
        parsed_data["original_phishing_email"] = extract_original_email(parsed_data["email_content"])
        parsed_data["original_phishing_email"]["container_path"] = container_path
        parsed_data["original_phishing_email"]["reconstruction_method"] = "direct"
    
    return parsed_data

def is_forwarded_email(msg):
    """
    Check if the email is a forwarded email based on various indicators.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        bool: True if it's a forwarded email, False otherwise
    """
    # Check subject for forwarding indicators
    subject = msg.get('Subject', '')
    if subject.lower().startswith(('fw:', 'fwd:')):
        return True
    
    # Check content for forwarding patterns
    body = extract_body(msg)
    body_text = body['plain'] + body['html']
    
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
    # For now, we'll return a placeholder
    return {
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

def is_embedded_email(content):
    """
    Check if content is an embedded email.
    
    Args:
        content (str): Content to check
        
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
        if pattern.lower() in content.lower():
            header_count += 1
    
    # If we find at least 3 header patterns, it's likely an embedded email
    return header_count >= 3

def is_likely_phishing_email(email_data):
    """
    Determine if an email is likely to be the original phishing email.
    
    Args:
        email_data (dict): Parsed email data
        
    Returns:
        bool: True if likely a phishing email, False otherwise
    """
    # Implement heuristics to identify phishing emails
    # For now, a simple implementation
    
    # Check for suspicious URLs
    suspicious_url_patterns = [
        "login", "verify", "confirm", "account", "secure", "update", "bank", 
        "paypal", "amazon", "microsoft", "google", "apple", "password"
    ]
    
    urls = []
    if "urls" in email_data:
        urls = email_data["urls"]
    elif "email_content" in email_data and "body" in email_data["email_content"]:
        body = email_data["email_content"]["body"]
        urls = extract_urls(body["plain"] + " " + body["html"])
    
    for url in urls:
        url_str = url.get("original_url", "").lower()
        for pattern in suspicious_url_patterns:
            if pattern in url_str:
                return True
    
    # Check subject for suspicious keywords
    subject = ""
    if "subject" in email_data:
        subject = email_data["subject"]
    elif "email_content" in email_data and "subject" in email_data["email_content"]:
        subject = email_data["email_content"]["subject"]
    
    suspicious_subject_patterns = [
        "urgent", "attention", "important", "alert", "verify", "confirm", 
        "account", "password", "security", "update", "bank", "suspicious"
    ]
    
    for pattern in suspicious_subject_patterns:
        if pattern in subject.lower():
            return True
    
    # Check for authentication failures
    if "email_content" in email_data:
        if email_data["email_content"].get("dkim_result", "").lower() == "fail":
            return True
        if email_data["email_content"].get("spf_result", "").lower() == "fail":
            return True
        if email_data["email_content"].get("dmarc_result", "").lower() == "fail":
            return True
    
    return False

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
        "body": {
            "plain": "",
            "html": ""
        },
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
        original_email["body"] = email_data["body"]
    if "attachments" in email_data:
        original_email["attachments"] = email_data["attachments"]
    
    return original_email