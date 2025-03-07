import logging
import hashlib
import base64
import quopri
import os
import re
from email.message import Message

def extract_attachments(msg, depth=0, max_depth=10, container_path=None):
    """
    Extract attachments from an email message.
    
    Args:
        msg (email.message.Message): Email message object
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        list: List of attachment information dictionaries
    """
    if container_path is None:
        container_path = []
    
    logging.debug(f"Extracting attachments at depth {depth}")
    attachments = []
    
    # Handle multipart messages
    if msg.is_multipart():
        logging.debug("Message is multipart, processing parts")
        for part in msg.get_payload():
            # Check if it's an attachment
            if is_attachment(part):
                attachment = process_attachment(part, depth, max_depth, container_path)
                if attachment:
                    attachments.append(attachment)
            
            # Recursively process nested multipart parts
            elif part.is_multipart():
                logging.debug("Found nested multipart, recursively extracting attachments")
                nested_attachments = extract_attachments(
                    part, depth, max_depth, container_path
                )
                attachments.extend(nested_attachments)
    
    # Handle single part message with attachment
    elif is_attachment(msg):
        attachment = process_attachment(msg, depth, max_depth, container_path)
        if attachment:
            attachments.append(attachment)
    
    logging.debug(f"Found {len(attachments)} attachments")
    return attachments

def is_attachment(part):
    """
    Determine if a message part is an attachment.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        bool: True if it's an attachment, False otherwise
    """
    # Check Content-Disposition header
    content_disposition = part.get("Content-Disposition", "")
    if "attachment" in content_disposition.lower():
        return True
    
    # Check if part has a filename
    filename = get_filename(part)
    if filename:
        return True
    
    # Check if it's an embedded message
    if part.get_content_type().lower() == "message/rfc822":
        return True
    
    # Check Content-ID for inline attachments
    if part.get("Content-ID"):
        return True
    
    return False

def get_filename(part):
    """
    Extract filename from message part.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        str: Filename or empty string if not found
    """
    # Try Content-Disposition header
    content_disposition = part.get("Content-Disposition", "")
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    if filename_match:
        return filename_match.group(1)
    
    # Try Content-Type header
    content_type = part.get("Content-Type", "")
    filename_match = re.search(r'name="([^"]+)"', content_type)
    if filename_match:
        return filename_match.group(1)
    
    return ""

def process_attachment(part, depth, max_depth, container_path):
    """
    Process an attachment part and extract relevant information.
    Ignores image attachments completely.
    
    Args:
        part (email.message.Message): Email message part
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Attachment information dictionary or None if it's an image
    """
    try:
        filename = get_filename(part)
        content_type = part.get_content_type()
        
        # Skip image attachments
        if content_type.startswith('image/'):
            logging.debug(f"Skipping image attachment: {filename}, type: {content_type}")
            return None
            
        content_id = part.get("Content-ID", "")
        
        # Clean up Content-ID if it's in angle brackets
        if content_id and content_id.startswith("<") and content_id.endswith(">"):
            content_id = content_id[1:-1]
        
        logging.debug(f"Processing attachment: {filename}, type: {content_type}")
        
        # Get the attachment content
        content = part.get_payload(decode=True)
        if content is None:
            logging.warning(f"Empty attachment content for {filename}")
            content = b""
        
        # Calculate SHA256 hash
        sha256 = hashlib.sha256(content).hexdigest()
        
        # Check if it's an embedded email
        is_email = False
        parsed_email = None
        
        if content_type.lower() == "message/rfc822":
            is_email = True
            if depth < max_depth:
                logging.debug(f"Found embedded email, recursively parsing at depth {depth+1}")
                # Import here to avoid circular import
                from parsers.email_parser import parse_email
                
                # For embedded emails, get the payload (which should be a list with the message)
                embedded_msg = part.get_payload()[0]
                parsed_email = parse_email(
                    embedded_msg.as_string(),
                    depth + 1,
                    max_depth,
                    container_path + ["attachment"]
                )
            else:
                logging.warning(f"Maximum recursion depth ({max_depth}) reached, not parsing embedded email")
        
        # Extract text from attachment for indexing
        attachment_text = ""
        if content_type.startswith("text/"):
            try:
                charset = part.get_content_charset() or 'utf-8'
                attachment_text = content.decode(charset, errors='replace')
            except Exception as e:
                logging.warning(f"Failed to decode attachment text: {str(e)}")
                attachment_text = content.decode('utf-8', errors='replace')
        
        attachment = {
            "attachment_name": filename,
            "attachment_sha256": sha256,
            "content_type": content_type,
            "size": len(content),
            "content_id": content_id,
            "is_email": is_email,
            "attachment_text": attachment_text
        }
        
        if parsed_email:
            attachment["parsed_email"] = parsed_email
        
        return attachment
        
    except Exception as e:
        logging.error(f"Error processing attachment: {str(e)}")
        return None