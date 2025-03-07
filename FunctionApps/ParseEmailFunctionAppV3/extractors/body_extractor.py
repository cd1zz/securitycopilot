import logging
import re

def extract_body(msg):
    """
    Extract and process the body content of an email message.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Dictionary with body text content
    """
    logging.debug("Extracting body content from email message")
    
    # Import the strip_html_tags function
    from extractors.url_extractor import strip_html_tags
    
    # Initialize plain and html content
    plain_content = ""
    html_content = ""
    
    # Handle multipart messages
    if msg.is_multipart():
        logging.debug("Message is multipart, processing parts")
        logging.debug(f"Number of parts: {len(msg.get_payload())}")
        
        for i, part in enumerate(msg.get_payload()):
            content_type = part.get_content_type().lower()
            logging.debug(f"Part {i}: Content-Type: {content_type}")
            
            # Collect text content
            if content_type == "text/plain":
                decoded_content = decode_content(part)
                logging.debug(f"Found text/plain part of length {len(decoded_content)}")
                if len(decoded_content) > 0:
                    logging.debug(f"First 100 chars: {decoded_content[:100]}")
                plain_content += decoded_content
            
            # Collect HTML content
            elif content_type == "text/html":
                decoded_content = decode_content(part)
                logging.debug(f"Found text/html part of length {len(decoded_content)}")
                if len(decoded_content) > 0:
                    logging.debug(f"First 100 chars: {decoded_content[:100]}")
                html_content += decoded_content
            
            # Recursively process nested multipart messages
            elif part.is_multipart():
                logging.debug(f"Found nested multipart in part {i}, recursively extracting")
                nested_body = extract_body(part)
                if isinstance(nested_body, dict) and "body" in nested_body:
                    nested_body_content = nested_body["body"]
                    logging.debug(f"Found nested body of length {len(nested_body_content)}")
                    # If no plain content yet, use the nested body
                    if not plain_content:
                        plain_content = nested_body_content
    
    # Handle single part messages
    else:
        content_type = msg.get_content_type().lower()
        logging.debug(f"Message is single part with content-type: {content_type}")
        content = decode_content(msg)
        logging.debug(f"Decoded content length: {len(content)}")
        if len(content) > 0:
            logging.debug(f"First 100 chars: {content[:100]}")
        
        if content_type == "text/plain":
            plain_content = content
        elif content_type == "text/html":
            html_content = content
    
    # Prioritize plain text content
    if plain_content:
        logging.debug(f"Returning plain text content of length {len(plain_content)}")
        return {"body": plain_content}
    
    # If no plain text, extract text from HTML using strip_html_tags
    if html_content:
        try:
            logging.debug("Stripping HTML tags from content")
            text = strip_html_tags(html_content)
            text = re.sub(r'\s+', ' ', text).strip()
            logging.debug(f"Returning HTML-derived content of length {len(text)}")
            return {"body": text}
        except Exception as e:
            logging.error(f"Error stripping HTML tags: {str(e)}")
            text = re.sub(r'<[^>]+>', ' ', html_content)
            text = re.sub(r'\s+', ' ', text).strip()
            logging.debug(f"Returning regex-stripped HTML content of length {len(text)}")
            return {"body": text}
    
    # No content found
    logging.warning("No content found in message")
    return {"body": ""}

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