import logging
from email.message import Message
import re
import base64
import quopri

def extract_body(msg):
    """
    Extract and process the body content of an email message.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Dictionary containing plain text and HTML body content
    """
    logging.debug("Extracting body content from email message")
    
    body = {
        "plain": "",
        "html": ""
    }
    
    # Handle multipart messages
    if msg.is_multipart():
        logging.debug("Message is multipart, processing parts")
        for part in msg.get_payload():
            content_type = part.get_content_type().lower()
            
            # Process text parts
            if content_type == "text/plain":
                body["plain"] += decode_content(part)
            
            # Process HTML parts
            elif content_type == "text/html":
                body["html"] += decode_content(part)
            
            # Recursively process nested multipart messages
            elif part.is_multipart():
                logging.debug("Found nested multipart, recursively extracting")
                nested_body = extract_body(part)
                body["plain"] += nested_body["plain"]
                body["html"] += nested_body["html"]
    
    # Handle single part messages
    else:
        content_type = msg.get_content_type().lower()
        content = decode_content(msg)
        
        if content_type == "text/plain":
            body["plain"] = content
        elif content_type == "text/html":
            body["html"] = content
        else:
            # For unrecognized content types, default to plain text
            logging.warning(f"Unrecognized content type: {content_type}, treating as plain text")
            body["plain"] = content
    
    logging.debug(f"Body extraction complete. Plain text length: {len(body['plain'])}, HTML length: {len(body['html'])}")
    return body

def decode_content(part):
    """
    Decode the content of an email part based on its encoding.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        str: Decoded content as string
    """
    # Get content and encoding
    content = part.get_payload(decode=True)
    encoding = part.get_content_charset()
    
    if content is None:
        logging.warning("Content is None, returning empty string")
        return ""
    
    # Handle different content transfer encodings
    transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()
    logging.debug(f"Decoding content with transfer encoding: {transfer_encoding}")
    
    try:
        # Convert bytes to string if needed
        if isinstance(content, bytes):
            if encoding:
                try:
                    logging.debug(f"Decoding with charset: {encoding}")
                    content = content.decode(encoding, errors='replace')
                except (LookupError, UnicodeDecodeError) as e:
                    logging.warning(f"Error decoding with {encoding}: {str(e)}. Falling back to utf-8")
                    content = content.decode('utf-8', errors='replace')
            else:
                logging.debug("No charset specified, using utf-8 with replace error handling")
                content = content.decode('utf-8', errors='replace')
        
        return content
        
    except Exception as e:
        logging.error(f"Error decoding content: {str(e)}")
        if isinstance(content, bytes):
            return content.decode('utf-8', errors='replace')
        return str(content)