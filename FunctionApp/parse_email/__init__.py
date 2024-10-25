import json
import re
import hashlib
import tldextract
import ipaddress
import logging
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import List, Dict
import azure.functions as func
import urllib.parse 
import requests
from bs4 import BeautifulSoup

# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.DEBUG)

# String found in all MSFT safelinks urls
SAFELINKS_SUB_DOMAIN = "safelinks.protection.outlook.com"

# List of known URL shortener domains
URL_SHORTENER_PROVIDERS = [
    "bit.ly",
    "t.co",
    "goo.gl",
    "ow.ly",
    "tinyurl.com",
    "is.gd",
    "buff.ly",
    "rebrandly.com",
    "cutt.ly",
    "bl.ink",
    "snip.ly",
    "su.pr",
    "lnkd.in",
    "fb.me",
    "cli.gs",
    "sh.st",
    "mcaf.ee",
    "yourls.org",
    "v.gd",
    "s.id",
    "t.ly",
    "tiny.cc",
    "qlink.me",
    "po.st",
    "short.io"
]


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
    Extracts the original email from a raw email byte string, particularly if it's an attachment.

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
            elif content_type == "message/rfc822" and "attachment" in content_disposition:
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
    try:
        # Pattern to extract domains and URLs
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

        # Find all URLs first
        urls = re.findall(url_pattern, content)

        # Parse domains from URLs
        url_domains = {urllib.parse.urlparse(url).netloc.lower() for url in urls}

        # Find all domain patterns directly
        direct_domains = [domain.lower() for domain in re.findall(domain_pattern, content)]

        # Combine and clean up
        all_domains = url_domains.union(direct_domains)

        valid_domains = {
            f"{extracted.domain}.{extracted.suffix}"
            for domain in all_domains
            if (extracted := tldextract.extract(domain)).domain and extracted.suffix
        }

        return list(valid_domains)
    except re.error as e:
        logger.error(f"Regex error extracting domains: {e}")
        return []
    except Exception as e:
        logger.error(f"General error extracting domains: {e}")
        return []


def get_attachments(email_message: EmailMessage) -> List[Dict[str, str]]:
    """
    Retrieves the attachments from an email and calculates their SHA-256 hash.

    Parameters:
    email_message (EmailMessage): The email message object.

    Returns:
    List[Dict[str, str]]: A list of dictionaries containing attachment names and their SHA-256 hash values.
    """
    attachments = []
    for part in email_message.iter_attachments():
        try:
            if part.get_filename():
                attachment_data = {
                    'attachment_name': part.get_filename(),
                    'attachment_sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
                }
                attachments.append(attachment_data)
        except Exception as e:
            logger.error(f"Error processing attachment: {e}")
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

    # Extract IP addresses using the new `extract_ips` function
    ipv4_addresses, ipv6_addresses = extract_ips(content)

    # Regex pattern to extract URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    regex_urls = re.findall(url_pattern, content)

    # Extract URLs using BeautifulSoup
    html_urls = extract_urls_from_html(content)

    # Combine URLs from regex and BeautifulSoup extraction
    all_urls = list(set(regex_urls + html_urls))

    # Decode SafeLink URLs only if the domain matches the SafeLink domain
    decoded_urls = [
        decode_safelink_url(url) if SAFELINKS_SUB_DOMAIN in urllib.parse.urlparse(url).netloc.lower() else url
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
            # Remove any trailing HTML tags or characters
            url = re.sub(r'<.*?>$', '', url)  # Remove trailing HTML tags
            url = url.rstrip('/.,;!')  # Remove trailing punctuation marks
            cleaned_urls.append(url)
        except re.error as e:
            logger.error(f"Regex error cleaning URL {url}: {e}")
        except Exception as e:
            logger.error(f"General error cleaning URL {url}: {e}")
    return cleaned_urls


def get_body(email_message: EmailMessage) -> str:
    """
    Extracts the body content from an email message, handling both multipart and non-multipart emails.

    Parameters:
    email_message (EmailMessage): The email message object to extract the body from.

    Returns:
    str: The extracted body content of the email as a string. If the email is multipart,
         the function joins all relevant parts, otherwise it returns the decoded payload.
    """
    if email_message.is_multipart():
        logger.info("Email is multipart, iterating over parts")
        parts = [
            get_body(part).strip()
            for part in email_message.iter_parts()
            if part.is_multipart() or part.get_content_type() in ['text/plain', 'text/html']
        ]
        return "\n".join(part for part in parts if part)
    else:
        logger.info("Email is not multipart, extracting payload directly")
        payload = email_message.get_payload(decode=True)
        charset = email_message.get_content_charset() or 'utf-8'
        return payload.decode(charset).strip() if payload else ""
    

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

    Parameters:
    body (str): The body content of the email as a string.

    Returns:
    str: The forwarded message content if found, or None if no forwarding indicator is present.
    """
    logger.info("Checking for forwarded message in body")
    split_keywords = ["---------- Forwarded message ---------", "-----Original Message-----"]
    for keyword in split_keywords:
        if keyword in body:
            parts = body.split(keyword, 1)
            logger.info("Forwarded message keyword found, extracting forwarded content")
            forwarded_content = parts[1].strip()
            forwarded_body = "\n".join(forwarded_content.split('\n')[4:]).strip()
            return forwarded_body
    logger.info("No forwarded message keyword found in body")
    return None


def parse_email(raw_email: bytes) -> Dict:
    """
    Parses a raw email byte string and extracts key metadata and content.

    Parameters:
    raw_email (bytes): The raw email content in bytes.

    Returns:
    Dict: A dictionary containing parsed email details, including:
        - sender (str): The email address of the sender.
        - return_path (str): The return path address from the email headers.
        - receiver (str): The email address of the receiver.
        - reply_to (str): The reply-to email address.
        - subject (str): The subject line of the email.
        - date (str): The date when the email was sent.
        - smtp (Dict): SMTP information including delivered-to and received headers.
        - dkim_result (str): The DKIM authentication result.
        - spf_result (str): The SPF authentication result.
        - dmarc_result (str): The DMARC authentication result.
        - body (str): The plain text body of the email, including forwarded content if present.
        - attachments (List[Dict[str, str]]): A list of attachments, each with name and SHA-256 hash.

    Returns None if an error occurs during parsing, with details logged.

    Exceptions:
    Logs an error message and returns None if any parsing error occurs.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)

        sender = msg.get('From', '') or ""
        return_path = msg.get('Return-Path', '') or ""
        receiver = msg.get('To', '') or ""
        subject = msg.get('Subject', '') or ""
        reply_to = msg.get('Reply-To', '') or ""
        date = msg.get('Date', '') or ""
        body = get_body(msg)
    
        # Extract forwarded message if present
        forwarded_body = extract_forwarded_message(body)
        if forwarded_body:
            logger.info("Forwarded message found and extracted")
            body = forwarded_body
        else:
            logger.info("No forwarded message found")

        dkim_result = parse_authentication_results(msg.get_all('ARC-Authentication-Results', []), "dkim=")
        if dkim_result == "none":
            dkim_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "dkim=")

        spf_result = parse_spf(msg.get_all('Received-SPF', []))
        if spf_result == "none":
            spf_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "spf=")

        dmarc_result = parse_authentication_results(msg.get_all('ARC-Authentication-Results', []), "dmarc=")
        if dmarc_result == "none":
            dmarc_result = parse_authentication_results(msg.get_all('Authentication-Results', []), "dmarc=")

        smtp = {
            "delivered_to": msg.get('Delivered-To', '') or "",
            "received": msg.get_all('Received', []) or []
        }

        attachments = get_attachments(msg)

        email_data = {
            "sender": sender,
            "return_path": return_path,
            "receiver": receiver,
            "reply_to": reply_to,
            "subject": subject,
            "date": date,
            "smtp": smtp,
            "dkim_result": dkim_result,
            "spf_result": spf_result,
            "dmarc_result": dmarc_result,
            "body": body,
            "attachments": attachments,
        }

        return email_data
    except Exception as e:
        logger.error(f"Error parsing email: {str(e)}")
        return None


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


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure function main handler that processes an incoming HTTP request containing a raw email.

    Parameters:
    req (func.HttpRequest): The HTTP request object.

    Returns:
    func.HttpResponse: The HTTP response object containing parsed email data or an error message.
    """
    logger.info('Python HTTP trigger function processed a request.')

    try:
        raw_email = req.get_body()

        if isinstance(raw_email, str):
            raw_email = raw_email.encode('utf-8')

        original_email = extract_original_email(raw_email)
        parsed_email_data = parse_email(original_email.encode())

        if parsed_email_data:
            all_domains, all_ip_addresses, all_urls = recursive_parse(parsed_email_data)

            result = {
                "email_content": parsed_email_data,
                "ip_addresses": list(all_ip_addresses),
                "urls": list(all_urls),
                "domains": list(all_domains),
            }

            # Apply the strip_html_tags function to the email content's body
            result["email_content"]["body"] = strip_html_tags(result["email_content"]["body"])

            json_result = json.dumps(result, indent=4)
            return func.HttpResponse(json_result, mimetype="application/json")
        else:
            logger.error("Failed to parse email.")
            return func.HttpResponse("Failed to parse email.", status_code=400)

    except ValueError as e:
        logger.error(f"Value error processing request: {e}")
        return func.HttpResponse(f"Value error: {e}", status_code=400)
    except TypeError as e:
        logger.error(f"Type error processing request: {e}")
        return func.HttpResponse(f"Type error: {e}", status_code=400)
    except Exception as e:
        logger.error(f"General error processing request: {e}")
        return func.HttpResponse(f"Error: {e}", status_code=500)
