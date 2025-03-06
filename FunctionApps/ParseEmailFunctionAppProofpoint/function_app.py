import azure.functions as func
import logging
import re
import hashlib
import tldextract
import ipaddress
import json
import traceback
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.policy import EmailPolicy
from typing import List, Dict, Any
import urllib.parse 
import requests
from bs4 import BeautifulSoup
from tnefparse import TNEF
from parse_pdf import extract_and_clean_pdf_text
from parse_excel import extract_and_clean_excel_text

logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger("AzureFunction")
logger.setLevel(logging.DEBUG)

# Define global regex patterns
URL_PATTERN = r'\bhttps?://[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
DOMAIN_PATTERN = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

# Proofpoint email body & header markers
PROOFPOINT_HEADER_MARKER_BEGIN = "---------- Begin Email Headers ----------"
PROOFPOINT_HEADER_MARKER_END = "---------- End Email Headers ----------"
PROOFPOINT_BODY_MARKER_BEGIN = "---------- Begin Reported Email ----------"
PROOFPOINT_BODY_MARKER_END = "---------- End Reported Email ----------"

# String found in all MSFT safelinks urls
SAFELINKS_SUB_DOMAIN = "safelinks.protection.outlook.com"

# String found in all Proofpoint urldefense urls
URLDEFENSE_DOMAIN = "urldefense.com"

# List of known URL shortener domains
URL_SHORTENER_PROVIDERS = ["bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly", "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in", "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id", "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at", "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im", "x.co", "d.pr", "rb.gy", "vk.cc", "t1p.de", "chilp.it", "ouo.io", "zi.ma", "pd.am", "hyperurl.co", "tiny.ie", "qps.ru", "l.ead.me", "shorte.st"]

# Fixes a bug https://github.com/python/cpython/issues/94306 related to malformed message-id headers
class CustomEmailPolicy(EmailPolicy):
    def header_fetch_parse(self, name, value):
        if name == 'Message-ID':
            if isinstance(value, str) and ('[' in value or ']' in value):
                # Strip square brackets from Message-ID
                return re.sub(r'[\[\]]', '', value)
        return super().header_fetch_parse(name=name, value=value)

# Set up the Function App
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="", methods=["POST"])
def parse_email_function(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure function main handler that processes an incoming HTTP request containing
    either a raw email or a Proofpoint-reported email.
    """
    logger.info('Python HTTP trigger function processed a request.')

    try:
        # Get raw input 
        raw_input = req.get_body()
        
        # Convert bytes to string if needed for initial processing
        if isinstance(raw_input, bytes):
            raw_input_str = raw_input.decode('utf-8', errors='ignore')
        else:
            raw_input_str = raw_input
            raw_input = raw_input_str.encode('utf-8')
        
        # Extract subject for Proofpoint detection
        subject = extract_subject_from_raw_input(raw_input_str)
        logger.info(f"Detected subject: {subject}")
        
        # Check if this is a Proofpoint-reported email
        is_proofpoint = is_proofpoint_reported_email(subject, raw_input_str)
        logger.info(f"Is Proofpoint-reported email: {is_proofpoint}")
        
        if is_proofpoint:
            logger.info("Processing as Proofpoint-reported email format")
            
            # Parse using the Proofpoint extraction method
            extracted_data = extract_from_proofpoint_email(raw_input_str)
            
            # Log the extracted headers to help with debugging
            logger.debug(f"Extracted Proofpoint headers: {json.dumps(extracted_data['headers'], default=str)}")
            
            # Convert the extracted data to a format matching our existing processing
            parsed_email_data = convert_proofpoint_to_parsed_email(extracted_data)
        else:
            logger.info("Processing as standard email")
            
            # Use the rollback version's extraction method for better message/rfc822 handling
            original_email = extract_original_email(raw_input)
            
            # Convert to bytes if it's a string for parsing
            if isinstance(original_email, str):
                original_email = original_email.encode('utf-8')
                
            parsed_email_data = parse_email(original_email)

        if parsed_email_data:
            # Log the parsed data structure before extraction for debugging
            logger.debug(f"Parsed email structure: {json.dumps(parsed_email_data, default=str)}")
            
            all_domains, all_ip_addresses, all_urls = recursive_parse(parsed_email_data)

            # Clean domains to remove any leading '2f' or '40'
            all_domains = clean_domains(all_domains)

            # Convert all_urls to a list for deduplication
            url_list = list(all_urls)

            # Apply base URL deduplication if URL list length exceeds 20
            if len(url_list) > 20:
                url_list = dedupe_to_base_urls(url_list)
                logger.info(f"Deduplicated URL count: {len(url_list)}")
            else:
                logger.info("URL count is 20 or below; skipping deduplication")

            result = {
                "email_content": parsed_email_data,
                "ip_addresses": list(all_ip_addresses),
                "urls": url_list,
                "domains": list(all_domains),
            }

            # Apply the strip_html_tags function to the email content's body and remove excessive newlines
            result["email_content"]["body"] = strip_html_tags(result["email_content"]["body"])
            result["email_content"]["body"] = clean_excessive_newlines(result["email_content"]["body"])

            json_result = json.dumps(result, indent=4)
            return func.HttpResponse(json_result, mimetype="application/json")
        else:
            logger.error("Failed to parse email.")
            return func.HttpResponse("Failed to parse email.", status_code=400)

    except ValueError as e:
        logger.error(f"Value error processing request: {e}")
        logger.debug("Stack Trace:", exc_info=True)
        return func.HttpResponse(f"Value error: {e}", status_code=400)
    except TypeError as e:
        logger.error(f"Type error processing request: {e}")
        logger.debug("Stack Trace:", exc_info=True)
        return func.HttpResponse(f"Type error: {e}", status_code=400)
    except Exception as e:
        logger.error(f"General error processing request: {e}")
        logger.debug("Stack Trace:", exc_info=True)
        return func.HttpResponse(f"Error: {e}\n{traceback.format_exc()}", status_code=500)

def is_proofpoint_reported_email(subject, body):
    """
    Determines if an email is a Proofpoint-reported phishing email.
    
    Args:
        subject (str): Email subject line
        body (str): Email body content
        
    Returns:
        bool: True if this is a Proofpoint-reported email, False otherwise
    """
    logger.info("Checking if email is a Proofpoint-reported phishing email")
    
    # Check for the characteristic subject pattern, allowing for forwarded emails
    subject_match = subject and "Potential Phish:" in subject
    logger.debug(f"Subject match for Proofpoint: {subject_match}")
    
    # More lenient pattern matching for body markers
    body_match = False

    logger.debug(f"Check email body for proofpoint markers: {body}")
    # Original strict check
    if PROOFPOINT_HEADER_MARKER_BEGIN in body and PROOFPOINT_HEADER_MARKER_END in body:
        body_match = True
        logger.debug("Found standard header markers in body")
    
    # More lenient checks for forwarded or modified Proofpoint reports
    elif "Begin Email Headers" in body and "End Email Headers" in body:
        body_match = True
        logger.debug("Found modified header markers in body")
    
    # Additional check for Proofpoint reported content
    elif PROOFPOINT_BODY_MARKER_BEGIN in body:
        body_match = True
        logger.debug("Found reported email marker in body")
    
    logger.debug(f"Email body markers match for Proofpoint: {body_match}")
    
    # Log the determination logic details for debugging
    result = subject_match and body_match
    if subject_match and not body_match:
        logger.info("Subject matches Proofpoint pattern but body markers not found")
        # Log a sample of the body for debugging
        logger.debug(f"Body sample: {body[:500]}...")
    
    logger.info(f"Is Proofpoint email determination: {result}")
    
    return result

def extract_from_proofpoint_email(body):
    """
    Extracts email components from a Proofpoint-reported phishing email.
    
    Args:
        body (str): The body of the Proofpoint-reported email
        
    Returns:
        dict: Contains extracted headers and content
    """
    logger.info("Extracting content from Proofpoint-reported email")
    
    # Extract the headers section with a more robust pattern
    headers_pattern = rf"{re.escape(PROOFPOINT_HEADER_MARKER_BEGIN)}\r?\n(.*?)\r?\n{re.escape(PROOFPOINT_HEADER_MARKER_END)}"
    headers_match = re.search(headers_pattern, body, re.DOTALL)
    headers_text = headers_match.group(1) if headers_match else ""
    logger.info(f"Extracted headers length: {len(headers_text)}")
    
    # Extract the email content with a more robust pattern
    content_pattern = rf"{re.escape(PROOFPOINT_BODY_MARKER_BEGIN)}\r?\n(.*?)(?:\r?\n{re.escape(PROOFPOINT_BODY_MARKER_END)}|$)"
    content_match = re.search(content_pattern, body, re.DOTALL)
    email_content = content_match.group(1) if content_match else ""
    logger.info(f"Extracted content length: {len(email_content)}")
    
    # Parse headers manually by splitting into lines and processing
    header_dict = {}
    current_header = None
    current_value = None
    
    # Split headers by lines and process
    for line in headers_text.splitlines():
        # Skip empty lines
        if not line.strip():
            continue
            
        # If line starts with space/tab, it's a continuation of the previous header
        if line[0] in ' \t' and current_header:
            current_value += ' ' + line.strip()
        # Otherwise it's a new header
        elif ':' in line:
            # Save the previous header if there was one
            if current_header:
                header_dict[current_header] = current_value.strip()
                
            # Start a new header
            parts = line.split(':', 1)
            current_header = parts[0].strip()
            current_value = parts[1].strip() if len(parts) > 1 else ""
    
    # Add the last header if there is one
    if current_header and current_value is not None:
        header_dict[current_header] = current_value.strip()
    
    logger.debug(f"Parsed headers: {len(header_dict)} found")
    
    return {
        "headers": header_dict,
        "content": email_content
    }

def extract_attachments_from_proofpoint_content(content):
    """
    Extracts attachment information from Proofpoint-reported email content.
    
    Args:
        content (str): The content section of a Proofpoint-reported email
        
    Returns:
        list: List of attachment dictionaries
    """
    logger.info("Extracting attachments from Proofpoint content")
    
    # This is a placeholder function that will need to be implemented
    # based on how attachments appear in Proofpoint emails
    
    # For now, return an empty list
    return []

def convert_proofpoint_to_parsed_email(extracted_data):
    """
    Converts Proofpoint-extracted data to match the format of parse_email() output.
    
    Args:
        extracted_data (dict): Data extracted from Proofpoint-reported email
        
    Returns:
        dict: Email data in the same format as parse_email() output
    """
    logger.info("Converting Proofpoint data to standard format")
    
    headers = extracted_data["headers"]
    content = extracted_data["content"]
    
    # Extract key headers with proper case-insensitive lookup
    def get_header(name, default=''):
        for key in headers:
            if key.lower() == name.lower():
                return headers[key]
        return default
    
    # Extract authentication results
    auth_results = get_header('Authentication-Results', '')
    if isinstance(auth_results, list):
        auth_results = '; '.join(auth_results)
    
    # Get received headers as a list
    received_headers = []
    for key in headers:
        if key.lower() == 'received':
            if isinstance(headers[key], list):
                received_headers.extend(headers[key])
            else:
                received_headers.append(headers[key])
    
    email_data = {
        "message_id": get_header('Message-ID'),
        "sender": get_header('From'),
        "return_path": get_header('Return-Path'),
        "receiver": get_header('To'),
        "reply_to": get_header('Reply-To'),
        "subject": get_header('Subject'),
        "date": get_header('Date'),
        "smtp": {
            "delivered_to": get_header('Delivered-To'),
            "received": received_headers
        },
        "dkim_result": parse_authentication_results([auth_results], "dkim="),
        "spf_result": parse_authentication_results([auth_results], "spf="),
        "dmarc_result": parse_authentication_results([auth_results], "dmarc="),
        "body": content,
        "attachments": extract_attachments_from_proofpoint_content(content),
    }
    
    logger.info(f"Converted email data: message_id={email_data['message_id']}, sender={email_data['sender']}")
    
    return email_data

def extract_subject_from_raw_input(raw_input_str):
    """
    Extracts the subject line from raw email input.
    
    Parameters:
    raw_input_str (str): Raw email content as a string
    
    Returns:
    str: The extracted subject or empty string if not found
    """
    logger.info("Extracting subject from raw input")
    
    # Try to extract subject line using regex
    subject_match = re.search(r"Subject: (.*?)(\r?\n[^ \t]|\Z)", raw_input_str, re.DOTALL)
    if subject_match:
        # Clean up any newlines or spaces in the subject
        subject = re.sub(r"\r?\n\s+", " ", subject_match.group(1).strip())
        logger.debug(f"Found subject: {subject}")
        return subject
    
    logger.debug("No subject found in raw input")
    return ""

def extract_original_email(raw_email: bytes) -> str:
    """
    Extracts the original email from a raw email byte string, particularly if it's an attachment.
    Now handles both standard emails and those with message/rfc822 attachments.
    
    Parameters:
    raw_email (bytes): The raw email content in bytes.
    
    Returns:
    str: The original email as a string or the provided raw email if extraction fails.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception as e:
        logger.error(f"Error parsing raw email: {e}")
        return raw_email.decode('utf-8', errors='ignore')

    original_email = None
    found_rfc822 = False

    # Extract email parts
    try:
        for part in msg.walk():
            content_type = part.get_content_type()
            main_content_type = part.get_content_maintype()
            content_disposition = part.get("Content-Disposition", None)

            if main_content_type == 'multipart':
                continue
            elif content_type == "message/rfc822":
                found_rfc822 = True
                logger.info("Raw MSG extracted.")
                original_email = part.get_payload(0)
    except Exception as e:
        logger.error(f"Error while extracting original email content: {e}")
        return raw_email.decode('utf-8', errors='ignore')

    if found_rfc822 and original_email:
        return original_email.as_string()
    else:
        logger.info("No MSG attachment found.")
        return raw_email.decode('utf-8', errors='ignore')

def get_body(msg: EmailMessage) -> str:
    """
    Extracts only the body content from an email message.
    Always returns a string.
    """
    if msg.is_multipart():
        logger.info("Processing multipart message")
        # Get all text/plain parts
        text_parts = []
        html_parts = []  # Add this to handle HTML parts too
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        text_parts.append(content.decode('utf-8', errors='ignore'))
                except Exception as e:
                    logger.error(f"Error processing text/plain part: {e}")
            elif content_type == 'text/html':  # Add HTML part handling
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        html_parts.append(content.decode('utf-8', errors='ignore'))
                except Exception as e:
                    logger.error(f"Error processing text/html part: {e}")
        
        # Prioritize text parts over HTML parts
        if text_parts:
            return '\n'.join(text_parts)
        elif html_parts:  # Return HTML if no text parts found
            return '\n'.join(html_parts)
        else:
            return ""
    else:
        logger.info("Processing single part message")
        try:
            content = msg.get_payload(decode=True)
            return content.decode('utf-8', errors='ignore') if content else ""
        except Exception as e:
            logger.error(f"Error processing single part content: {e}")
            return ""

def parse_email(raw_email: bytes) -> Dict:
    """
    Parses a raw email byte string and extracts key metadata and content.
    Handles message/rfc822, TNEF, and regular email formats.
    
    Parameters:
    raw_email (bytes): Raw email content as bytes
    
    Returns:
    Dict: Dictionary containing parsed email data
    """
    try:
        # First extract the original email with proper TNEF and message/rfc822 handling
        original_email = extract_original_email(raw_email)
        
        # Convert to bytes if needed and parse with custom policy
        if isinstance(original_email, str):
            original_email = original_email.encode('utf-8')
            
        custom_policy = CustomEmailPolicy(raise_on_defect=False)
        msg = BytesParser(policy=custom_policy).parsebytes(original_email)

        # Initialize header fields with default empty values
        email_headers = {
            "message_id": "",
            "sender": "",
            "return_path": "",
            "receiver": "",
            "subject": "",
            "reply_to": "",
            "date": ""
        }

        # Extract header fields with error handling
        try:
            email_headers = {
                "message_id": msg.get('Message-ID', ''),
                "sender": msg.get('From', ''),
                "return_path": msg.get('Return-Path', ''),
                "receiver": msg.get('To', ''),
                "subject": msg.get('Subject', ''),
                "reply_to": msg.get('Reply-To', ''),
                "date": msg.get('Date', '')
            }
        except Exception as e:
            logger.error(f"Error extracting header fields: {e}")

        # Check for message/rfc822 parts first
        rfc822_found = False
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'message/rfc822':
                    logger.info("Processing message/rfc822 part")
                    try:
                        # Get the embedded message
                        embedded_msg = part.get_payload()[0]
                        # Update headers from embedded message (only if new values exist)
                        email_headers = {
                            "message_id": embedded_msg.get('Message-ID', '') or email_headers["message_id"],
                            "sender": embedded_msg.get('From', '') or email_headers["sender"],
                            "return_path": embedded_msg.get('Return-Path', '') or email_headers["return_path"],
                            "receiver": embedded_msg.get('To', '') or email_headers["receiver"],
                            "subject": embedded_msg.get('Subject', '') or email_headers["subject"],
                            "reply_to": embedded_msg.get('Reply-To', '') or email_headers["reply_to"],
                            "date": embedded_msg.get('Date', '') or email_headers["date"]
                        }
                        msg = embedded_msg  # Use embedded message for further processing
                        rfc822_found = True
                        break
                    except Exception as e:
                        logger.error(f"Error processing message/rfc822 part: {e}")

        # If no message/rfc822 found, check for forwarded message
        if not rfc822_found:
            forwarded_msg = extract_forwarded_message_attachment(msg, custom_policy)
            if forwarded_msg:
                logger.info("Forwarded message attachment found, re-parsing as standalone email")
                try:
                    # Update headers from forwarded message (only if new values exist)
                    email_headers = {
                        "message_id": forwarded_msg.get('Message-ID', '') or email_headers["message_id"],
                        "sender": forwarded_msg.get('From', '') or email_headers["sender"],
                        "return_path": forwarded_msg.get('Return-Path', '') or email_headers["return_path"],
                        "receiver": forwarded_msg.get('To', '') or email_headers["receiver"],
                        "subject": forwarded_msg.get('Subject', '') or email_headers["subject"],
                        "reply_to": forwarded_msg.get('Reply-To', '') or email_headers["reply_to"],
                        "date": forwarded_msg.get('Date', '') or email_headers["date"]
                    }
                    msg = forwarded_msg  # Use forwarded message for further processing
                except Exception as e:
                    logger.error(f"Error processing forwarded message: {e}")

        # Get body content
        body = get_body(msg)

        # Check for text-based forwarded content if no other forwarded content found
        if not rfc822_found and not forwarded_msg:
            forwarded_body = extract_forwarded_message(body)
            if forwarded_body:
                logger.info("Forwarded message text detected, attempting re-parsing")
                try:
                    forwarded_msg = BytesParser(policy=custom_policy).parsebytes(forwarded_body.encode('utf-8'))
                    # Update headers from forwarded text (only if new values exist)
                    email_headers = {
                        "message_id": forwarded_msg.get('Message-ID', '') or email_headers["message_id"],
                        "sender": forwarded_msg.get('From', '') or email_headers["sender"],
                        "return_path": forwarded_msg.get('Return-Path', '') or email_headers["return_path"],
                        "receiver": forwarded_msg.get('To', '') or email_headers["receiver"],
                        "subject": forwarded_msg.get('Subject', '') or email_headers["subject"],
                        "reply_to": forwarded_msg.get('Reply-To', '') or email_headers["reply_to"],
                        "date": forwarded_msg.get('Date', '') or email_headers["date"]
                    }
                    body = get_body(forwarded_msg)
                except Exception as e:
                    logger.error(f"Error re-parsing forwarded message text: {e}")

        # Parse authentication results
        dkim_result = parse_authentication_results(msg.get_all('ARC-Authentication-Results', []), "dkim=")
        if dkim_result == "none":
            dkim_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "dkim=")

        spf_result = parse_spf(msg.get_all('Received-SPF', []))
        if spf_result == "none":
            spf_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "spf=")

        dmarc_result = parse_authentication_results(msg.get_all('ARC-Authentication-Results', []), "dmarc=")
        if dmarc_result == "none":
            dmarc_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "dmarc=")

        # Get SMTP information
        smtp = {
            "delivered_to": msg.get('Delivered-To', ''),
            "received": msg.get_all('Received', [])
        }

        # Process attachments
        attachments = get_attachments(msg)
        processed_attachments = []
        for attachment in attachments:
            content_type = attachment["content_type"]
            if content_type in {"application/pdf", "application/x-pdf", "application/octet-stream"}:
                try:
                    pdf_text = extract_and_clean_pdf_text(attachment["attachment_base64"])
                    processed_attachments.append({
                        "attachment_name": attachment["attachment_name"],
                        "attachment_sha256": attachment["attachment_sha256"],
                        "content_type": content_type,
                        "attachment_text": pdf_text
                    })
                except Exception as e:
                    logger.error(f"Failed to parse PDF {attachment['attachment_name']}: {e}")
                    processed_attachments.append({
                        "attachment_name": attachment["attachment_name"],
                        "attachment_sha256": attachment["attachment_sha256"],
                        "content_type": content_type,
                        "error": str(e)
                    })
            elif content_type in {
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.ms-excel",
                "application/msexcel",
                "application/x-msexcel",
                "application/x-ms-excel",
                "application/x-excel",
                "application/x-dos_ms_excel",
                "application/xls",
                "application/x-xls"
            }:
                try:
                    excel_text = extract_and_clean_excel_text(attachment["attachment_base64"])
                    processed_attachments.append({
                        "attachment_name": attachment["attachment_name"],
                        "attachment_sha256": attachment["attachment_sha256"],
                        "content_type": content_type,
                        "attachment_text": excel_text
                    })
                except Exception as e:
                    logger.error(f"Failed to parse Excel file {attachment['attachment_name']}: {e}")
                    processed_attachments.append({
                        "attachment_name": attachment["attachment_name"],
                        "attachment_sha256": attachment["attachment_sha256"],
                        "content_type": content_type,
                        "error": str(e)
                    })
            else:
                processed_attachments.append({
                    "attachment_name": attachment["attachment_name"],
                    "attachment_sha256": attachment["attachment_sha256"],
                    "content_type": content_type
                })

        # Construct final email data dictionary
        email_data = {
            "message_id": email_headers["message_id"],
            "sender": email_headers["sender"],
            "return_path": email_headers["return_path"],
            "receiver": email_headers["receiver"],
            "reply_to": email_headers["reply_to"],
            "subject": email_headers["subject"],
            "date": email_headers["date"],
            "smtp": smtp,
            "dkim_result": dkim_result,
            "spf_result": spf_result,
            "dmarc_result": dmarc_result,
            "body": body,
            "attachments": processed_attachments,
        }

        return email_data

    except Exception as e:
        logger.error(f"Error in parse_email: {e}", exc_info=True)
        raise  # Re-raise the exception for the caller to handle

def extract_forwarded_message_attachment(msg: EmailMessage, policy) -> EmailMessage:
    """
    Iterates over the MIME parts of the given email message and returns the first part
    with Content-Type 'message/rfc822', re-parsed as an EmailMessage using the given policy.
    Returns None if no such part is found.
    """
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'message/rfc822':
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        forwarded_msg = BytesParser(policy=policy).parsebytes(payload)
                        return forwarded_msg
                except Exception as e:
                    logger.error(f"Error parsing forwarded message attachment: {e}")
    return None

def extract_forwarded_message(body: str) -> str:
    """
    Extracts the content of a forwarded message from the email body if a forwarding keyword is present.
    Returns the forwarded content as a well-formed RFC822-like string.
    """
    logger.info("Checking for forwarded message in body")
    split_keywords = ["---------- Forwarded message ---------", "-----Original Message-----"]
    for keyword in split_keywords:
        if keyword in body:
            parts = body.split(keyword, 1)
            logger.info("Forwarded message keyword found, extracting forwarded content")
            forwarded_content = parts[1].strip()
            # Remove the delimiter line if it's still present and any extra blank lines at the start
            lines = forwarded_content.splitlines()
            # If the first line starts with a delimiter marker, remove it
            if lines and lines[0].strip().startswith("-----"):
                lines = lines[1:]
            # Remove leading blank lines
            while lines and not lines[0].strip():
                lines.pop(0)
            forwarded_body = "\n".join(lines).strip()
            return forwarded_body
    logger.info("No forwarded message keyword found in body")
    return None

def parse_authentication_results(headers, keyword):
    """
    Parses email headers to extract authentication results based on a specific keyword.

    Parameters:
    headers (List[str]): A list of email header strings to be parsed.
    keyword (str): The keyword to search for in the authentication results (e.g., "dkim=", "spf=", "dmarc=").

    Returns:
    str: A string containing the matching authentication results separated by semicolons, or "none" if no matches are found.
    """
    results = []
    for header in headers:
        parts = header.split(";")
        for part in parts:
            if keyword in part:
                results.append(part.strip())
    return "; ".join(results) if results else "none"

def parse_spf(headers):
    """
    Parses email headers to extract SPF (Sender Policy Framework) results.

    Parameters:
    headers (List[str]): A list of email header strings to be parsed.

    Returns:
    str: A string containing the SPF results separated by semicolons, or "none" if no SPF results are found.
    """
    results = []
    for header in headers:
        if header.startswith("Received-SPF"):
            results.append(header.strip())
    return "; ".join(results) if results else "none"

def get_attachments(email_message: EmailMessage) -> List[Dict[str, str]]:
    """
    Retrieves the attachments from an email, calculates their SHA-256 hash, 
    and extracts the attachment as a base64-encoded string along with content type.

    Parameters:
    email_message (EmailMessage): The email message object.

    Returns:
    List[Dict[str, str]]: A list of dictionaries containing attachment names, 
                          their SHA-256 hash values, base64-encoded content, and content type.
    """
    attachments = []
    logger.info("Starting to extract attachments from email.")

    for part in email_message.iter_attachments():
        try:
            logger.info(f"Processing attachment: {part.get_filename()}")

            if part.get_filename():
                # Get the base64 string of the file (without decoding to raw bytes)
                file_base64 = part.get_payload(decode=False)
                logger.info(f"Retrieved base64 string for attachment: {part.get_filename()}")

                # Decode base64 to bytes for SHA-256 hash calculation
                file_bytes = part.get_payload(decode=True)
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                logger.info(f"Calculated SHA-256 hash for attachment '{part.get_filename()}': {sha256_hash}")

                # Get content type
                content_type = part.get_content_type()
                logger.info(f"Content type for attachment '{part.get_filename()}': {content_type}")

                attachment_data = {
                    'attachment_name': part.get_filename(),
                    'attachment_sha256': sha256_hash,
                    'attachment_base64': file_base64,
                    'content_type': content_type
                }

                attachments.append(attachment_data)
                logger.info(f"Attachment '{part.get_filename()}' processed and added to list.")
        except Exception as e:
            logger.error(f"Error processing attachment '{part.get_filename()}': {e}")

    logger.info("Finished extracting attachments from email.")
    return attachments

def strip_html_tags(text: str) -> str:
    """
    Strips all HTML tags from a given text string.

    Parameters:
    text (str): The HTML content as a string.

    Returns:
    str: A plain text string with all HTML tags removed.
    """
    return BeautifulSoup(text, "html.parser").get_text()

def clean_excessive_newlines(text):
    # Replace multiple consecutive newlines (2 or more) with a single newline
    cleaned_text = re.sub(r'\n{2,}', '\n', text)
    return cleaned_text

def clean_domains(domains: set) -> set:
    """
    Removes leading '2f' or '40' (case-insensitive) from each domain in the provided set.

    Parameters:
    domains (set): A set of domain strings to be cleaned.

    Returns:
    set: A set of cleaned domains with no leading '2f' or '40'.
    """
    cleaned_domains = set()
    for domain in domains:
        # Remove leading '2f' or '40' (case-insensitive)
        cleaned_domain = re.sub(r'^(?i:2f|40)', '', domain)
        cleaned_domains.add(cleaned_domain)
    return cleaned_domains

def is_public_ip(ip: str) -> bool:
    """
    Determines if the given IP address is a public IP address.

    Parameters:
    ip (str): The IP address as a string.

    Returns:
    bool: True if the IP address is public, False otherwise (including private, reserved, multicast, loopback, link-local, unspecified, or invalid IP addresses).
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip == '255.255.255.255')
    except ValueError:
        return False

def extract_ips(text: str):
    # A simple regex to match potential IP addresses (IPv4 and IPv6 candidates)
    potential_ips = re.findall(r'\b[a-fA-F0-9:.]+\b', text)
    
    ipv4_addresses = []
    ipv6_addresses = []

    for ip in potential_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                ipv4_addresses.append(ip)
            elif ip_obj.version == 6:
                ipv6_addresses.append(ip)
        except ValueError:
            # Ignore if not a valid IP address
            continue

    return ipv4_addresses, ipv6_addresses

def extract_urls_from_html(content: str) -> List[str]:
    """
    Extracts URLs from the HTML content of an email.

    Parameters:
    content (str): The HTML content as a string.

    Returns:
    List[str]: A list of extracted URLs or an empty list if extraction fails.
    """
    try:
        soup = BeautifulSoup(content, "html.parser")
        urls = [a['href'] for a in soup.find_all('a', href=True)]
        return urls
    except Exception as e:
        logger.error(f"Error extracting URLs from HTML content: {e}")
        return []

def is_image_url(url: str) -> bool:
    """
    Determines if a given URL points to an image file based on its extension.

    Parameters:
    url (str): The URL to be checked.

    Returns:
    bool: True if the URL points to an image, False otherwise.
    """
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']
    parsed_url = urllib.parse.urlparse(url)
    return any(parsed_url.path.lower().endswith(ext) for ext in image_extensions)

def clean_urls(urls: List[str]) -> List[str]:
    """
    Cleans the provided URLs by removing unwanted trailing characters and HTML tags.

    Parameters:
    urls (List[str]): A list of URLs to be cleaned.

    Returns:
    List[str]: A list of cleaned URLs.
    """
    cleaned_urls = []
    for url in urls:
        try:
            # Remove any HTML tags using the strip_html_tags function
            url = strip_html_tags(url)

            # Ensure only the URL part is retained (cut off any extraneous words)
            match = re.match(URL_PATTERN, url)
            if match:
                cleaned_urls.append(match.group(0))
            else:
                logger.info(f"Regex did not match URL {url}")
        except re.error as e:
            logger.error(f"Regex error cleaning URL {url}: {e}")
        except Exception as e:
            logger.error(f"General error cleaning URL {url}: {e}")
    
    return cleaned_urls

def decode_safelink_url(safelink: str) -> str:
    """
    Decodes a Microsoft SafeLink URL to retrieve the original URL.

    Parameters:
    safelink (str): The SafeLink URL to be decoded.

    Returns:
    str: The decoded original URL, or the original SafeLink if decoding fails.
    """
    logger.info(f"Attempting to decode SafeLink URL: {safelink}")
    try:
        parsed_url = urllib.parse.urlparse(safelink)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]

        if original_url:
            decoded_url = urllib.parse.unquote(original_url)
            logger.info(f"Successfully decoded SafeLink URL to: {decoded_url}")
            return decoded_url
        else:
            logger.info("SafeLink URL could not be decoded, returning original.")
            return safelink  # Return the original SafeLink if 'url' parameter is missing
    except Exception as e:
        logger.error(f"Error decoding SafeLink URL {safelink}: {e}")
        return safelink # Return the original SafeLink if 'url' parameter is missing

def decode_proofpoint_url(urldefense: str) -> str:
    try:
        # Check if the URL starts with the Proofpoint pattern
        if URLDEFENSE_DOMAIN in urldefense:
            # Decode the URL
            decoded_url = urllib.parse.unquote(urldefense)

            # Extract the original URL (after "__https:" and before ";")
            start_marker = "__"
            end_marker = ";"
            
            if start_marker in decoded_url and end_marker in decoded_url:
                start_idx = decoded_url.index(start_marker) + len(start_marker)
                end_idx = decoded_url.index(end_marker)
                original_url = decoded_url[start_idx:end_idx]

                # Add "https://" back if it was removed
                if original_url.startswith("https:/"):
                    original_url = original_url.replace("https:/", "https://")
                elif original_url.startswith("http:/"):
                    original_url = original_url.replace("http:/", "http://")
                logger.info(f"{urldefense} decoded to url: {original_url}.")
                return original_url
        else:
            logger.info(f"{urldefense} is not a proofpoint url.")
            return urldefense

    except Exception as e:
        return f"Error decoding URL: {e}"

def expand_url(url: str) -> str:
    """
    Attempts to expand a shortened URL by following redirects.
    If the final connection cannot be made, returns the last known location.

    Parameters:
    url (str): The URL to be expanded.

    Returns:
    str: The expanded URL, or the last known URL if connection fails.
    """
    logger.info(f"Attempting to expand shortened URL: {url}")

    try:
        # Use the GET request here to capture redirections properly and store them
        session = requests.Session()
        response = session.head(url, allow_redirects=True, timeout=5)

        # Capture the final URL
        expanded_url = response.url
        logger.info(f"Successfully expanded URL: {expanded_url}")
        return expanded_url
    except requests.RequestException as e:
        logger.error(f"Connection error expanding shortened URL {url}: {e}")

        # Use history from the session object to retrieve the last valid redirection point
        if hasattr(e, 'response') and e.response is not None:
            logger.info(f"Returning last known redirect URL from history: {e.response.url}")
            return e.response.url
        
        if hasattr(e, 'request'):
            last_redirected_url = e.request.url
            logger.info(f"Returning last known redirected URL from request: {last_redirected_url}")
            return last_redirected_url

        # Attempt HTTP if HTTPS failed
        if url.startswith("https://"):
            fallback_url = url.replace("https://", "http://", 1)
            logger.info(f"Retrying with HTTP: {fallback_url}")
            try:
                response = session.head(fallback_url, allow_redirects=True, timeout=5)
                expanded_url = response.url
                logger.info(f"Successfully expanded URL with HTTP: {expanded_url}")
                return expanded_url
            except requests.RequestException as e:
                logger.error(f"Failed to expand with HTTP fallback: {e}")

                # Attempt to return the last successful redirection URL if available
                if hasattr(e, 'request'):
                    last_redirected_url = e.request.url
                    logger.info(f"Returning last known redirected URL from HTTP fallback: {last_redirected_url}")
                    return last_redirected_url

    # Return the original URL if we couldn't expand it at all
    logger.info(f"Returning original URL, as no expansion could be made: {url}")
    return url

def parse_ip_and_urls(content: str) -> Dict[str, List[str]]:
    """
    Parses the given email content to extract IP addresses and URLs.

    Parameters:
    content (str): The email content as a string.

    Returns:
    Dict[str, List[str]]: A dictionary containing:
        - 'ip_addresses' (List[str]): A list of unique public IP addresses extracted from the content.
        - 'urls' (List[str]): A list of cleaned and expanded URLs extracted from the content, excluding image URLs.
    """
    logger.info("Parsing email content for IP addresses and URLs")

    # Extract IP addresses using the `extract_ips` function
    ipv4_addresses, ipv6_addresses = extract_ips(content)

    # Regex pattern to extract URLs - Tweaked to prevent trailing text from being captured
    regex_urls = re.findall(URL_PATTERN, content)

    # Extract URLs using BeautifulSoup
    html_urls = extract_urls_from_html(content)

    # Combine URLs from regex and BeautifulSoup extraction
    all_urls = list(set(regex_urls + html_urls))

    # Decode SafeLink URLs and Proofpoint URLs based on their respective domains
    decoded_urls = [
        decode_safelink_url(url) if SAFELINKS_SUB_DOMAIN in urllib.parse.urlparse(url).netloc.lower() else
        decode_proofpoint_url(url) if URLDEFENSE_DOMAIN in urllib.parse.urlparse(url).netloc.lower() else
        url
        for url in all_urls
    ]

    # Clean the URLs
    cleaned_urls = clean_urls(decoded_urls)

    # Expand shortened URLs if their domain is in the known shortener list
    expanded_urls = [
        expand_url(url) if urllib.parse.urlparse(url).netloc.lower() in URL_SHORTENER_PROVIDERS else url
        for url in cleaned_urls
    ]

    # Filter out image URLs
    non_image_urls = [url for url in expanded_urls if not is_image_url(url)]

    # Combine IPv4 and IPv6 addresses and filter out non-public IP addresses
    all_ip_addresses = list(set(ipv4_addresses + ipv6_addresses))
    filtered_ip_addresses = [ip for ip in all_ip_addresses if is_public_ip(ip)]

    return {
        'ip_addresses': filtered_ip_addresses,
        'urls': non_image_urls
    }

def extract_domains(content: str) -> List[str]:
    """
    Extracts domain names from the email content.

    Parameters:
    content (str): The email content as a string.

    Returns:
    List[str]: A list of valid domain names found in the content, or an empty list if an error occurs.
    """
    logger.info("Extracting domains from email content")
    logger.debug(f"Incoming content for domain extraction: {content}")
    try:
        # Find all URLs first
        urls = re.findall(URL_PATTERN, content)
        logger.debug(f"Found URLs: {urls}")

        # Decode URLs and parse domains
        url_domains = set()
        for url in urls:
            decoded_url = urllib.parse.unquote(url)
            extracted_domain = tldextract.extract(decoded_url).fqdn.lower()
            logger.debug(f"Original URL: {url}, Decoded URL: {decoded_url}, Extracted Domain: {extracted_domain}")
            url_domains.add(extracted_domain)

        # Find all direct domain patterns and parse without URL decoding
        direct_domains = set()
        for domain in re.findall(DOMAIN_PATTERN, content):
            extracted_domain = tldextract.extract(domain).fqdn.lower()
            logger.debug(f"Direct match domain: {domain}, Extracted Domain: {extracted_domain}")
            direct_domains.add(extracted_domain)

        # Combine and filter valid domains
        valid_domains = {
            domain for domain in url_domains.union(direct_domains)
            if domain and '.' in domain  # Ensures valid domain format
        }
        
        logger.debug(f"Final list of valid domains: {valid_domains}")

        return list(valid_domains)
    except re.error as e:
        logger.error(f"Regex error extracting domains: {e}")
        return []
    except Exception as e:
        logger.error(f"General error extracting domains: {e}")
        return []

def recursive_parse(content):
    """
    Recursively parses email content to extract domains, IP addresses, and URLs.

    Parameters:
    content (Any): The email content, which may be a dictionary, list, or string.

    Returns:
    Tuple[Set[str], Set[str], Set[str]]: Sets of extracted domains, IP addresses, and URLs.
    """
    all_domains = set()
    all_ip_addresses = set()
    all_urls = set()

    if isinstance(content, dict):
        for key, value in content.items():
            try:
                domains, ips, urls = recursive_parse(value)
                all_domains.update(domains)
                all_ip_addresses.update(ips)
                all_urls.update(urls)
            except Exception as e:
                logger.error(f"Error while parsing key '{key}': {e}")
    elif isinstance(content, list):
        for item in content:
            try:
                domains, ips, urls = recursive_parse(item)
                all_domains.update(domains)
                all_ip_addresses.update(ips)
                all_urls.update(urls)
            except Exception as e:
                logger.error(f"Error while parsing list item: {e}")
    elif isinstance(content, str):
        try:
            all_domains.update(extract_domains(content))
            ip_and_urls = parse_ip_and_urls(content)
            all_ip_addresses.update(ip_and_urls['ip_addresses'])
            all_urls.update(ip_and_urls['urls'])
        except Exception as e:
            logger.error(f"Error parsing content string: {e}")

    return all_domains, all_ip_addresses, all_urls

def dedupe_to_base_urls(urls):
    """
    Deduplicates URLs by extracting and keeping only the unique base parts in the form 'http(s)://subdomain.domain.tld'.

    Parameters:
    urls (List[str]): List of URLs to deduplicate.

    Returns:
    List[str]: List of unique base URLs.
    """
    unique_bases = set()
    for url in urls:
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url not in unique_bases:
            unique_bases.add(base_url)
            logger.info(f"Adding unique base URL: {base_url}")
        else:
            logger.info(f"Duplicate base URL skipped: {base_url}")
    
    return list(unique_bases)