import logging
import re
from extractors.url_extractor import extract_urls
from extractors.ip_extractor import extract_ip_addresses
from extractors.domain_extractor import extract_domains

def is_proofpoint_email(email_content):
    """
    Determine if the email is in Proofpoint format.
    
    Args:
        email_content (str or bytes): Raw email content
        
    Returns:
        bool: True if it's a Proofpoint email
    """
    if isinstance(email_content, bytes):
        try:
            email_content = email_content.decode('utf-8', errors='replace')
        except Exception as e:
            logging.warning(f"Error decoding email content: {str(e)}")
            return False
    
    proofpoint_indicators = [
        "---------- Begin Email Headers ----------",
        "---------- End Email Headers ----------",
        "---------- Begin Reported Email ----------",
        "---------- End Reported Email ----------"
    ]
    
    # Check if at least 2 of the indicators are present
    indicator_count = sum(1 for indicator in proofpoint_indicators if indicator in email_content)
    return indicator_count >= 2

def parse_proofpoint_email(email_content, depth=0, max_depth=10, container_path=None):
    """
    Parse an email in Proofpoint format.
    
    Args:
        email_content (str or bytes): Raw email content
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Parsed email data
    """
    if container_path is None:
        container_path = []
    
    logging.debug("Parsing Proofpoint-formatted email")
    
    # Convert bytes to string if needed
    if isinstance(email_content, bytes):
        try:
            email_content = email_content.decode('utf-8', errors='replace')
        except Exception as e:
            logging.error(f"Error decoding Proofpoint email content: {str(e)}")
            return {"error": f"Failed to decode Proofpoint email content: {str(e)}"}
    
    # Initialize output structure
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
            "is_original_phishing_email": True,  # Proofpoint typically contains the original phishing email
            "email_depth": depth,
            "container_type": "proofpoint_report"
        },
        "ip_addresses": [],
        "urls": [],
        "domains": []
    }
    
    try:
        # Extract headers
        headers_match = re.search(
            r"---------- Begin Email Headers ----------([\s\S]*?)---------- End Email Headers ----------",
            email_content, 
            re.IGNORECASE
        )
        
        if headers_match:
            headers_text = headers_match.group(1).strip()
            logging.debug("Successfully extracted Proofpoint email headers")
            
            # Parse headers
            header_lines = headers_text.split('\n')
            current_header = None
            headers = {}
            
            for line in header_lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Check if this is a new header
                header_match = re.match(r'^([A-Za-z0-9\-]+):\s*(.*)', line)
                if header_match:
                    current_header = header_match.group(1)
                    headers[current_header] = header_match.group(2)
                elif current_header and line.startswith(' '):
                    # Continuation of previous header
                    headers[current_header] += ' ' + line.strip()
            
            # Map headers to output structure
            parsed_data["email_content"]["message_id"] = headers.get("Message-ID", "")
            parsed_data["email_content"]["sender"] = headers.get("From", "")
            parsed_data["email_content"]["return_path"] = headers.get("Return-Path", "")
            parsed_data["email_content"]["receiver"] = headers.get("To", "")
            parsed_data["email_content"]["reply_to"] = headers.get("Reply-To", "")
            parsed_data["email_content"]["subject"] = headers.get("Subject", "")
            parsed_data["email_content"]["date"] = headers.get("Date", "")
            
            # Extract SMTP info
            parsed_data["email_content"]["smtp"]["delivered_to"] = headers.get("Delivered-To", "")
            if "Received" in headers:
                parsed_data["email_content"]["smtp"]["received"] = [headers["Received"]]
            
            # Extract authentication results
            auth_results = headers.get("Authentication-Results", "")
            parsed_data["email_content"]["dkim_result"] = "pass" if "dkim=pass" in auth_results else "fail" if "dkim=fail" in auth_results else ""
            parsed_data["email_content"]["spf_result"] = "pass" if "spf=pass" in auth_results else "fail" if "spf=fail" in auth_results else ""
            parsed_data["email_content"]["dmarc_result"] = "pass" if "dmarc=pass" in auth_results else "fail" if "dmarc=fail" in auth_results else ""
            
            logging.debug(f"Parsed Proofpoint email headers: Subject={parsed_data['email_content']['subject']}, From={parsed_data['email_content']['sender']}")
        else:
            logging.warning("Could not find Proofpoint email headers section")
        
        # Extract email body
        body_match = re.search(
            r"---------- Begin Reported Email ----------([\s\S]*?)---------- End Reported Email ----------",
            email_content, 
            re.IGNORECASE
        )
        
        if body_match:
            body_text = body_match.group(1).strip()
            logging.debug("Successfully extracted Proofpoint email body")
            
            # Determine if body is HTML or plain text
            if "<html" in body_text.lower() or "<body" in body_text.lower():
                parsed_data["email_content"]["body"]["html"] = body_text
                # Simple HTML tag stripping for plain text version
                plain_text = re.sub(r'<[^>]+>', '', body_text)
                parsed_data["email_content"]["body"]["plain"] = plain_text
            else:
                parsed_data["email_content"]["body"]["plain"] = body_text
            
            # Extract URLs, IPs, and domains from the body
            body_combined = parsed_data["email_content"]["body"]["plain"] + " " + parsed_data["email_content"]["body"]["html"]
            parsed_data["urls"] = extract_urls(body_combined)
            parsed_data["ip_addresses"] = extract_ip_addresses(body_combined)
            parsed_data["domains"] = extract_domains(parsed_data["urls"])
            
            logging.debug(f"Extracted {len(parsed_data['urls'])} URLs, {len(parsed_data['ip_addresses'])} IP addresses, and {len(parsed_data['domains'])} domains")
        else:
            logging.warning("Could not find Proofpoint reported email body section")
        
        # Set this as the original phishing email since Proofpoint forwards are typically the original
        parsed_data["original_phishing_email"] = {
            "message_id": parsed_data["email_content"]["message_id"],
            "sender": parsed_data["email_content"]["sender"],
            "return_path": parsed_data["email_content"]["return_path"],
            "receiver": parsed_data["email_content"]["receiver"],
            "reply_to": parsed_data["email_content"]["reply_to"],
            "subject": parsed_data["email_content"]["subject"],
            "date": parsed_data["email_content"]["date"],
            "body": parsed_data["email_content"]["body"],
            "attachments": [],
            "container_path": container_path,
            "reconstruction_method": "proofpoint_report"
        }
        
    except Exception as e:
        logging.error(f"Error parsing Proofpoint email: {str(e)}")
        parsed_data["error"] = f"Failed to parse Proofpoint email: {str(e)}"
    
    return parsed_data