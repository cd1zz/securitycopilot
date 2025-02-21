import json
import re
import hashlib
import tldextract
from tnefparse import TNEF
import ipaddress
import logging
import traceback
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.policy import EmailPolicy  # Add this line
from typing import List, Dict
import azure.functions as func
import urllib.parse 
import requests
from bs4 import BeautifulSoup
from parse_pdf import extract_and_clean_pdf_text
from parse_excel import extract_and_clean_excel_text

# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.DEBUG)

# Define global regex patterns
#URL_PATTERN =  r'\b(?i:http|https)://[a-zA-Z0-9.\-/?&=%_:~#]+(?:\b|(?=[\s.,;!?]))'
URL_PATTERN = r'\bhttps?://[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
DOMAIN_PATTERN = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

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


def extract_original_email(raw_email: bytes) -> str:
    """
    Extracts the original email from a raw email byte string.
    Now handles both TNEF and message/rfc822 formats.
    """
    custom_policy = CustomEmailPolicy(raise_on_defect=False)
    
    try:
        # First parse the carrier email
        msg = BytesParser(policy=custom_policy).parsebytes(raw_email)
        logger.debug(f"Initial message content type: {msg.get_content_type()}")

        # First check for message/rfc822 parts
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'message/rfc822':
                    logger.info("Found message/rfc822 attachment")
                    try:
                        # Get the raw content of the message/rfc822 part
                        rfc822_content = part.get_payload(decode=True)
                        if rfc822_content:
                            return rfc822_content.decode('utf-8', errors='ignore')
                    except Exception as e:
                        logger.error(f"Error processing message/rfc822 content: {e}")

        # If no message/rfc822 found, try TNEF handling
        if msg.get_content_type() == 'application/ms-tnef':
            logger.info("Found TNEF message at root level")
            try:
                # Get the TNEF data
                tnef_data = msg.get_payload(decode=True)
                if tnef_data:
                    # Parse the TNEF data
                    tnef = TNEF(tnef_data)
                    
                    # Look for message content in TNEF
                    for attr in tnef.attributes:
                        if attr.name in ['rtfbody', 'body']:
                            logger.info(f"Found {attr.name} in TNEF attributes")
                            try:
                                return attr.data.decode('utf-8', errors='ignore')
                            except Exception as e:
                                logger.error(f"Error decoding TNEF {attr.name}: {e}")
                    
                    # If no body found in attributes, check attachments
                    for attachment in tnef.attachments:
                        if attachment.name.lower() == "message.rfc822":
                            logger.info("Found RFC822 message in TNEF attachments")
                            try:
                                # Parse the embedded message
                                embedded_msg = BytesParser(policy=custom_policy).parsebytes(attachment.data)
                                # Get only the body content
                                return get_body(embedded_msg)
                            except Exception as e:
                                logger.error(f"Error processing RFC822 attachment: {e}")
                                continue
            except Exception as e:
                logger.error(f"Error processing TNEF data: {e}")
        
        # If we get here, either it's not TNEF or TNEF processing failed
        # Try to get the body content directly
        logger.info("Attempting to get body content directly")
        content = get_body(msg)
        if content:
            return content
            
        # Final fallback: return empty string instead of raw email
        logger.warning("No valid content found")
        return ""
        
    except Exception as e:
        logger.error(f"Error in extract_original_email: {e}")
        return ""
    
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


def get_body(msg: EmailMessage) -> str:
    """
    Extracts only the body content from an email message.
    """
    if msg.is_multipart():
        logger.info("Processing multipart message")
        # Get all text/plain parts
        text_parts = []
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        text_parts.append(content.decode('utf-8', errors='ignore'))
                except Exception as e:
                    logger.error(f"Error processing multipart content: {e}")
        return '\n'.join(text_parts) if text_parts else ""
    else:
        logger.info("Processing single part message")
        try:
            content = msg.get_payload(decode=True)
            return content.decode('utf-8', errors='ignore') if content else ""
        except Exception as e:
            logger.error(f"Error processing single part content: {e}")
            return ""
    

def strip_html_tags(text: str) -> str:
    """
    Strips all HTML tags from a given text string.

    Parameters:
    text (str): The HTML content as a string.

    Returns:
    str: A plain text string with all HTML tags removed.
    """
    return BeautifulSoup(text, "html.parser").get_text()


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
            # Remove the delimiter line if it’s still present and any extra blank lines at the start
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


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure function main handler that processes an incoming HTTP request containing a raw email.

    Parameters:
    req (func.HttpRequest): The HTTP request object.

    Returns:
    func.HttpResponse: The HTTP response object containing parsed email data or an error message.
    """
    logger = logging.getLogger("AzureFunction")
    logger.info('Python HTTP trigger function processed a request.')

    try:
        raw_email = req.get_body()

        if isinstance(raw_email, str):
            raw_email = raw_email.encode('utf-8')

        original_email = extract_original_email(raw_email)
        parsed_email_data = parse_email(original_email.encode())

        if parsed_email_data:
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