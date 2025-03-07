# parsers/proofpoint_parser.py
import logging
import re
from extractors.url_extractor import extract_urls
from extractors.ip_extractor import extract_ip_addresses
from extractors.domain_extractor import extract_domains

logger = logging.getLogger(__name__)

# Define Proofpoint markers
PROOFPOINT_HEADER_MARKER_BEGIN = "---------- Begin Email Headers ----------"
PROOFPOINT_HEADER_MARKER_END = "---------- End Email Headers ----------"
PROOFPOINT_BODY_MARKER_BEGIN = "---------- Begin Reported Email ----------"
PROOFPOINT_BODY_MARKER_END = "---------- End Reported Email ----------"

# parsers/proofpoint_parser.py (continued)
def is_proofpoint_email(msg):
    """
    Determine if an email is a Proofpoint-reported phishing email.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        bool: True if it's a Proofpoint-reported email, False otherwise
    """
    # Check subject for Proofpoint pattern
    subject = msg.get('Subject', '')
    subject_match = subject and "Potential Phish:" in subject
    
    # Extract body content to check for Proofpoint markers
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain' or part.get_content_type() == 'text/html':
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        body += content.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.error(f"Error decoding content in is_proofpoint_email: {str(e)}")
    else:
        try:
            content = msg.get_payload(decode=True)
            if content:
                body += content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Error decoding content in is_proofpoint_email: {str(e)}")
    
    # Check for Proofpoint markers in body
    body_match = False
    if PROOFPOINT_HEADER_MARKER_BEGIN in body and PROOFPOINT_HEADER_MARKER_END in body:
        body_match = True
    elif "Begin Email Headers" in body and "End Email Headers" in body:
        body_match = True
    elif PROOFPOINT_BODY_MARKER_BEGIN in body:
        body_match = True
    
    # Both subject and body need to match
    return subject_match and body_match

def parse_proofpoint_email(email_content, depth=0, max_depth=10, container_path=None):
    """
    Parse a Proofpoint-reported phishing email.
    
    Args:
        email_content (bytes or str): Raw email content
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Parsed email data
    """
    if container_path is None:
        container_path = []
    
    logger.debug("Parsing Proofpoint-formatted email")
    
    # Convert bytes to string if needed
    if isinstance(email_content, bytes):
        try:
            email_content_str = email_content.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Error decoding Proofpoint email content: {str(e)}")
            return {"error": f"Failed to decode Proofpoint email content: {str(e)}"}
    else:
        email_content_str = email_content
    
    # Parse the email to handle multipart content
    from email import message_from_string, message_from_bytes
    if isinstance(email_content, bytes):
        msg = message_from_bytes(email_content)
    else:
        msg = message_from_string(email_content)
    
    # Initialize variables to store headers and content
    headers_text = ""
    reported_content = ""
    
    # Process all parts of the email
    if msg.is_multipart():
        logger.debug("Proofpoint email is multipart, processing all parts")
        for part in msg.walk():
            # Skip multipart containers
            if part.get_content_maintype() == 'multipart':
                continue
            
            # Get the content of this part
            part_content = part.get_payload(decode=True)
            if part_content is None:
                continue
            
            # Try to decode the content to string
            try:
                charset = part.get_content_charset() or 'utf-8'
                part_text = part_content.decode(charset, errors='replace')
            except Exception as e:
                logger.warning(f"Error decoding part: {str(e)}, trying utf-8")
                part_text = part_content.decode('utf-8', errors='replace')
            
            # Search for Proofpoint markers in this part
            found_headers, found_content = extract_proofpoint_sections(part_text)
            
            if found_headers:
                headers_text = found_headers
                logger.debug(f"Found headers in email part with content type: {part.get_content_type()}")
            
            if found_content:
                reported_content = found_content
                logger.debug(f"Found content in email part with content type: {part.get_content_type()}")
            
            # If we found both headers and content, we can stop processing parts
            if headers_text and reported_content:
                break
    else:
        # For non-multipart emails, check the entire content
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                payload_text = payload.decode(charset, errors='replace')
            except Exception as e:
                logger.warning(f"Error decoding payload: {str(e)}, trying utf-8")
                payload_text = payload.decode('utf-8', errors='replace')
            
            headers_text, reported_content = extract_proofpoint_sections(payload_text)
    
    # If no headers or content were found, try the original email content
    if not headers_text or not reported_content:
        headers_text_orig, reported_content_orig = extract_proofpoint_sections(email_content_str)
        if not headers_text:
            headers_text = headers_text_orig
        if not reported_content:
            reported_content = reported_content_orig
    
    # Log what we found
    logger.debug(f"Extracted headers length: {len(headers_text)}")
    if not headers_text:
        logger.warning("No headers extracted from Proofpoint email")
    
    logger.debug(f"Extracted content length: {len(reported_content)}")
    if not reported_content:
        logger.warning("No content extracted from Proofpoint email")
    
    # Parse headers manually
    header_dict = {}
    current_header = None
    current_value = None
    
    # Process headers line by line
    for line in headers_text.splitlines():
        # Skip empty lines
        if not line.strip():
            continue
            
        # If line starts with space/tab, it's a continuation
        if line and line[0] in ' \t' and current_header:
            current_value += ' ' + line.strip()
        # Otherwise it's a new header
        elif ':' in line:
            # Save the previous header
            if current_header:
                header_dict[current_header] = current_value.strip()
                
            # Start a new header
            parts = line.split(':', 1)
            current_header = parts[0].strip()
            current_value = parts[1].strip() if len(parts) > 1 else ""
    
    # Add the last header
    if current_header and current_value is not None:
        header_dict[current_header] = current_value.strip()
    
    # Extract authentication results
    auth_results = header_dict.get('Authentication-Results', '')
    
    # Extract DKIM, SPF, DMARC results
    dkim_result = "none"
    spf_result = "none"
    dmarc_result = "none"
    
    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
    if dkim_match:
        dkim_result = dkim_match.group(1)
    
    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
    if spf_match:
        spf_result = spf_match.group(1)
    
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
    if dmarc_match:
        dmarc_result = dmarc_match.group(1)
    
    # Get received headers as a list
    received_headers = []
    for key in header_dict:
        if key.lower() == 'received':
            received_headers.append(header_dict[key])
    
    # Look for and extract the original subject if it wasn't found in headers
    original_subject = header_dict.get('Subject', '')
    if not original_subject and reported_content:
        subject_match = re.search(r'Subject:[ \t]*([^\r\n]+)', reported_content, re.IGNORECASE)
        if subject_match:
            original_subject = subject_match.group(1).strip()
            logger.debug(f"Extracted subject from content: {original_subject}")
    
    # Look for sender information if it wasn't found in headers
    original_sender = header_dict.get('From', '')
    if not original_sender and reported_content:
        from_match = re.search(r'From:[ \t]*([^\r\n]+)', reported_content, re.IGNORECASE)
        if from_match:
            original_sender = from_match.group(1).strip()
            logger.debug(f"Extracted sender from content: {original_sender}")
    
    # Extract URLs and IP addresses from the reported content
    urls = extract_urls(reported_content)
    ip_addresses = extract_ip_addresses(reported_content)
    domains = extract_domains(urls)
    
    # If no subject was found yet, try to extract it from the Proofpoint subject
    if not original_subject:
        # Typical Proofpoint subject format: "Potential Phish: Original Email Subject"
        proofpoint_subject = msg.get('Subject', '')
        if 'Potential Phish:' in proofpoint_subject:
            original_subject = proofpoint_subject.split('Potential Phish:', 1)[1].strip()
            logger.debug(f"Extracted subject from Proofpoint subject line: {original_subject}")
    
    # Construct the email data
    email_data = {
        "email_content": {
            "message_id": header_dict.get('Message-ID', ''),
            "sender": original_sender,
            "return_path": header_dict.get('Return-Path', ''),
            "receiver": header_dict.get('To', ''),
            "reply_to": header_dict.get('Reply-To', ''),
            "subject": original_subject,
            "date": header_dict.get('Date', ''),
            "body": reported_content,
            "attachments": [],  
            "container_path": container_path + ["proofpoint"],
            "reconstruction_method": "proofpoint_reported",
            "urls": urls,
            "ip_addresses": ip_addresses,
            "domains": domains,
            "smtp": {
                "delivered_to": header_dict.get('Delivered-To', ''),
                "received": received_headers
            },
            "dkim_result": dkim_result,
            "spf_result": spf_result,
            "dmarc_result": dmarc_result
        }
    }
    
    # Add any additional useful Proofpoint-specific fields if they exist in headers
    proofpoint_fields = {
        "x_proofpoint_spam": header_dict.get('X-Proofpoint-Spam-Details', ''),
        "x_proofpoint_virus": header_dict.get('X-Proofpoint-Virus-Version', ''),
        "x_proofpoint_spam_score": header_dict.get('X-Proofpoint-Spam-Score', '')
    }
    
    # Only add non-empty Proofpoint fields
    proofpoint_data = {k: v for k, v in proofpoint_fields.items() if v}
    if proofpoint_data:
        email_data["email_content"]["proofpoint_metadata"] = proofpoint_data
    
    return email_data

def extract_proofpoint_sections(text):
    """
    Extract Proofpoint header and content sections from text.
    
    Args:
        text (str): Text to search for Proofpoint sections
        
    Returns:
        tuple: (headers_text, reported_content)
    """
    # Default empty values
    headers_text = ""
    reported_content = ""
    
    # Define patterns for headers
    header_patterns = [
        rf"{re.escape(PROOFPOINT_HEADER_MARKER_BEGIN)}\r?\n(.*?)\r?\n{re.escape(PROOFPOINT_HEADER_MARKER_END)}",
        r"[-]{2,15} Begin Email Headers [-]{0,15}\r?\n(.*?)\r?\n[-]{2,15} End Email Headers [-]{0,15}",
        r"Begin Email Headers\s*[-]*\s*\r?\n(.*?)\r?\nEnd Email Headers",
        r"Email Headers:\r?\n[-]{0,15}\r?\n(.*?)\r?\n[-]{0,15}"
    ]
    
    # Try each header pattern
    for pattern in header_patterns:
        headers_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if headers_match:
            headers_text = headers_match.group(1).strip()
            logger.debug(f"Found headers with pattern: {pattern[:30]}...")
            break
    
    # Define patterns for content
    content_patterns = [
        rf"{re.escape(PROOFPOINT_BODY_MARKER_BEGIN)}\r?\n(.*?)(?:\r?\n{re.escape(PROOFPOINT_BODY_MARKER_END)}|$)",
        r"[-]{2,15} Begin Reported Email [-]{0,15}\r?\n(.*?)(?:\r?\n[-]{2,15} End Reported Email [-]{0,15}|$)",
        r"Begin Reported Email\s*[-]*\s*\r?\n(.*?)(?:\r?\nEnd Reported Email|$)",
        r"Reported Email:\r?\n[-]{0,15}\r?\n(.*?)(?:\r?\n[-]{0,15}|$)"
    ]
    
    # Try each content pattern
    for pattern in content_patterns:
        content_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if content_match:
            reported_content = content_match.group(1).strip()
            logger.debug(f"Found content with pattern: {pattern[:30]}...")
            break
    
    return headers_text, reported_content