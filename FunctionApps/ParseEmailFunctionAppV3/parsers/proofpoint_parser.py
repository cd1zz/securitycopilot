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
            email_content = email_content.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Error decoding Proofpoint email content: {str(e)}")
            return {"error": f"Failed to decode Proofpoint email content: {str(e)}"}
    
    # Extract the header section
    headers_pattern = rf"{re.escape(PROOFPOINT_HEADER_MARKER_BEGIN)}\r?\n(.*?)\r?\n{re.escape(PROOFPOINT_HEADER_MARKER_END)}"
    headers_match = re.search(headers_pattern, email_content, re.DOTALL)
    headers_text = headers_match.group(1).strip() if headers_match else ""
    
    # Extract the email content
    content_pattern = rf"{re.escape(PROOFPOINT_BODY_MARKER_BEGIN)}\r?\n(.*?)(?:\r?\n{re.escape(PROOFPOINT_BODY_MARKER_END)}|$)"
    content_match = re.search(content_pattern, email_content, re.DOTALL)
    reported_content = content_match.group(1).strip() if content_match else ""
    
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
    
    # Extract URLs and IP addresses from the reported content
    urls = extract_urls(reported_content)
    ip_addresses = extract_ip_addresses(reported_content)
    domains = extract_domains(urls)
    
    # Construct the email data
    email_data = {
        "email_content": {
            "message_id": header_dict.get('Message-ID', ''),
            "sender": header_dict.get('From', ''),
            "return_path": header_dict.get('Return-Path', ''),
            "receiver": header_dict.get('To', ''),
            "reply_to": header_dict.get('Reply-To', ''),
            "subject": header_dict.get('Subject', ''),
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
    
    return email_data