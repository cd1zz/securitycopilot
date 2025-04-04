# utils/url_processor.py
import logging
import re
import urllib.parse
import requests
import time
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)

# Define URL pattern for extraction
URL_PATTERN = r'\bhttps?://[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'

# List of known URL shortener domains
URL_SHORTENER_PROVIDERS = [
    "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly", 
    "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in", 
    "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id", 
    "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at", 
    "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im", 
    "x.co", "d.pr", "rb.gy", "vk.cc", "t1p.de", "chilp.it", "ouo.io", 
    "zi.ma", "pd.am", "hyperurl.co", "tiny.ie", "qps.ru", "l.ead.me", 
    "shorte.st"
]

def extract_urls_by_content_type(content, content_type, filename=None):
    """
    Extract URLs from content based on its content type.
    
    Args:
        content: Content to extract URLs from (string or bytes)
        content_type: MIME type of the content
        filename: Optional filename for additional type detection
        
    Returns:
        list: List of extracted URLs
    """
    urls = []
    
    try:
        # If content is bytes, try to decode it
        if isinstance(content, bytes):
            try:
                # Try to detect charset from content_type
                charset = None
                if content_type and 'charset=' in content_type:
                    charset_match = re.search(r'charset=([^\s;]+)', content_type)
                    if charset_match:
                        charset = charset_match.group(1)
                
                # Fallback to utf-8
                charset = charset or 'utf-8'
                content = content.decode(charset, errors='replace')
            except Exception as e:
                logger.warning(f"Failed to decode content: {str(e)}")
                content = content.decode('utf-8', errors='replace')
        
        # HTML content
        if content_type and ('html' in content_type.lower() or 
                            (filename and filename.lower().endswith('.html'))):
            # Create a structure similar to what extract_all_urls_from_email expects
            from utils.html_processor import process_html_content
            processed_result = process_html_content(content)
            cleaned_text = processed_result.get("text", "")
            
            html_body_data = {
                "html": content,
                "body": cleaned_text
            }
            
            # Use the same function used by the main email parser
            urls = extract_all_urls_from_email(html_body_data)
            logger.debug(f"Extracted {len(urls)} URLs from HTML content")
            
        # PDF content
        elif (content_type and ('pdf' in content_type.lower())) or \
             (filename and filename.lower().endswith('.pdf')):
            # First extract text from PDF
            from extractors.pdf_extractor import extract_text_from_pdf
            try:
                if isinstance(content, str):
                    # Convert string back to bytes for PDF extraction
                    content = content.encode('utf-8', errors='replace')
                extracted_text = extract_text_from_pdf(content)
                
                # Then extract URLs from the extracted text
                urls = extract_urls(extracted_text)
                logger.debug(f"Extracted {len(urls)} URLs from PDF content")
            except Exception as e:
                logger.warning(f"Failed to extract URLs from PDF: {str(e)}")
                
        # Excel content
        elif (content_type and any(excel_type in content_type.lower() for excel_type in 
             ['excel', 'spreadsheet', 'xls'])) or \
             (filename and filename.lower().endswith(('.xls', '.xlsx'))):
            # First extract text from Excel
            from extractors.excel_extractor import extract_text_from_excel
            try:
                if isinstance(content, str):
                    # Convert string back to bytes for Excel extraction
                    content = content.encode('utf-8', errors='replace')
                extracted_text = extract_text_from_excel(content)
                
                # Then extract URLs from the extracted text
                urls = extract_urls(extracted_text)
                logger.debug(f"Extracted {len(urls)} URLs from Excel content")
            except Exception as e:
                logger.warning(f"Failed to extract URLs from Excel: {str(e)}")
                
        # Plain text and other content types
        else:
            urls = extract_urls(content)
            logger.debug(f"Extracted {len(urls)} URLs from text content")
            
        return urls
        
    except Exception as e:
        logger.error(f"Error extracting URLs from content: {str(e)}")
        return []

def extract_urls(text):
    """
    Extract URLs from text content.
    
    Args:
        text (str): Text content to extract URLs from
        
    Returns:
        list: List of dictionaries with URL information
    """
    if not text:
        return []
    
    # Decode quoted-printable encoding (common in email content)
    text = decode_quoted_printable(text)
    
    # Extract URLs using regex
    regex_urls = re.findall(URL_PATTERN, text)
    
    # Extract URLs from HTML if present using BeautifulSoup
    html_urls = extract_urls_from_html(text)
    
    # Combine and deduplicate URLs
    all_urls = list(set(regex_urls + html_urls))
    
    # Process each URL
    urls = []
    for url in all_urls:
        # Add www prefix if needed
        if url.startswith('www.'):
            url = 'http://' + url
        
        # Clean the URL
        url = clean_url(url)
        
        # Check if it's a shortened URL
        is_shortened = is_url_shortened(url)
        
        url_info = {
            "original_url": url,
            "is_shortened": is_shortened,
            "expanded_url": ""
        }
        
        urls.append(url_info)
    
    logger.debug(f"Extracted {len(urls)} URLs")
    return urls

def decode_quoted_printable(text):
    """
    Decode quoted-printable encoding in text, especially focused on URLs.
    
    Args:
        text (str): Text that may contain quoted-printable encoded content
        
    Returns:
        str: Decoded text
    """
    try:
        # Look for patterns like href=3D"http
        if "=3D" in text:
            # Use regex to find and replace quoted-printable sequences
            text = re.sub(r'=3D(["\'])(https?://[^"\']+)(\1)', r'=\1\2\3', text)
            
            # Try to use quopri for more comprehensive decoding
            import quopri
            from io import BytesIO
            
            # Only decode if it looks like quoted-printable
            if re.search(r'=[0-9A-F]{2}', text):
                encoded_text = text.encode('utf-8', errors='replace')
                decoded_text = quopri.decode(encoded_text)
                text = decoded_text.decode('utf-8', errors='replace')
        
        return text
    except Exception as e:
        logger.error(f"Error decoding quoted-printable content: {str(e)}")
        return text

def extract_urls_from_html(content):
    """
    Extracts URLs from HTML content using BeautifulSoup.
    
    Args:
        content (str): HTML content
        
    Returns:
        list: List of URLs found in HTML elements
    """
    try:
        soup = BeautifulSoup(content, "html.parser")
        urls = []
        
        # Extract from anchor tags
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                urls.append(href)
        
        # Extract from image sources
        for img in soup.find_all('img', src=True):
            src = img['src'].strip()
            if src and not src.startswith(('data:', 'cid:')):
                urls.append(src)
        
        # Extract from link tags
        for link in soup.find_all('link', href=True):
            href = link['href'].strip()
            if href:
                urls.append(href)
        
        # Extract from script sources
        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            if src:
                urls.append(src)
        
        # Extract from form actions
        for form in soup.find_all('form', action=True):
            action = form['action'].strip()
            if action and not action.startswith('#'):
                urls.append(action)
        
        # Extract URLs from inline styles
        for tag in soup.find_all(style=True):
            style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', tag['style'])
            urls.extend(style_urls)
        
        # Extract URLs from style tags
        for style in soup.find_all('style'):
            if style.string:
                style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', style.string)
                urls.extend(style_urls)
        
        return urls
    except Exception as e:
        logger.error(f"Error extracting URLs from HTML: {str(e)}")
        return []

def clean_url(url):
    """
    Clean a URL by removing trailing punctuation and normalizing.
    
    Args:
        url (str): URL to clean
        
    Returns:
        str: Cleaned URL
    """
    # Remove trailing punctuation
    while url and url[-1] in '.,;:!?)]}\'\"':
        url = url[:-1]
    
    # Try to normalize the URL
    try:
        # Parse the URL
        parsed = urllib.parse.urlparse(url)
        
        # Rebuild it to ensure proper formatting
        if parsed.scheme and parsed.netloc:
            return urllib.parse.urlunparse(parsed)
    except Exception as e:
        logger.warning(f"Error normalizing URL {url}: {str(e)}")
    
    return url

def is_url_shortened(url):
    """
    Check if a URL is likely to be shortened.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if it's likely a shortened URL, False otherwise
    """
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check if domain matches a known shortener
        if any(domain == shortener or domain.endswith('.' + shortener) for shortener in URL_SHORTENER_PROVIDERS):
            return True
        
        # Check for suspiciously short path (like 5-8 character hash)
        if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
            return True
    
    except Exception as e:
        logger.warning(f"Error checking if URL is shortened: {str(e)}")
    
    return False

def decode_safelinks(safelink):
    """
    Decode Microsoft SafeLinks URLs.
    
    Args:
        safelink (str): Microsoft SafeLink URL
        
    Returns:
        str: Decoded URL or original if decoding fails
    """
    logger.debug(f"Attempting to decode SafeLink")
    
    try:
        if "safelinks.protection.outlook.com" not in safelink:
            return safelink
            
        # Parse the URL
        parsed_url = urllib.parse.urlparse(safelink)
        
        # Extract the URL parameter
        query_params = urllib.parse.parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        
        if original_url:
            # URL decode the original URL
            decoded_url = urllib.parse.unquote(original_url)
            logger.debug(f"Successfully decoded SafeLink to: {decoded_url}")
            return decoded_url
        
        return safelink
    except Exception as e:
        logger.error(f"Error decoding SafeLink: {str(e)}")
        return safelink

def decode_proofpoint_urls(urldefense):
    """
    Decodes a Proofpoint URLDefense URL to extract the original URL.
    
    Args:
        urldefense (str): Proofpoint URLDefense URL
        
    Returns:
        str: The original URL or the input URL if decoding fails
    """
    logger.debug(f"Attempting to decode Proofpoint URL")
    
    try:
        if "urldefense.com" not in urldefense:
            return urldefense
            
        # URL decode first
        decoded_url = urllib.parse.unquote(urldefense)
        
        # Try to extract the original URL using different patterns
        
        # Pattern 1: u parameter
        if "u=" in decoded_url:
            parts = decoded_url.split("u=")
            if len(parts) > 1:
                u_value = parts[1].split("&")[0]
                return urllib.parse.unquote(u_value)
        
        # Pattern 2: __
        if "__" in decoded_url:
            parts = decoded_url.split("__")
            if len(parts) > 1:
                # Handle both http and https
                url_part = parts[1]
                if url_part.startswith("https:/"):
                    url_part = url_part.replace("https:/", "https://")
                elif url_part.startswith("http:/"):
                    url_part = url_part.replace("http:/", "http://")
                
                # Cut off at semicolon if present
                if ";" in url_part:
                    url_part = url_part.split(";")[0]
                    
                return url_part
                
        # If no pattern matched, return the original
        return urldefense
    except Exception as e:
        logger.error(f"Error decoding Proofpoint URL: {str(e)}")
        return urldefense

def expand_url(url, timeout=5, max_redirects=10):
    """
    Expands a shortened URL by following redirects.
    If the final connection cannot be made, returns the last known location.
    
    Args:
        url (str): URL to expand
        timeout (int): Request timeout in seconds
        max_redirects (int): Maximum number of redirects to follow
        
    Returns:
        str: The expanded URL or the original URL if expansion fails
    """
    if not url:
        return url
        
    # Check if URL is likely to be shortened
    is_shortened = is_url_shortened(url)
    if not is_shortened:
        return url
        
    logger.debug(f"Expanding shortened URL: {url}")
    
    try:
        # Ensure URL has a scheme
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url
        
        # Follow redirects with a HEAD request
        session = requests.Session()
        response = session.head(
            url,
            allow_redirects=True,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        
        # Get the final URL after redirects
        expanded_url = response.url
        
        logger.debug(f"URL expanded to: {expanded_url}")
        return expanded_url
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error expanding URL {url}: {str(e)}")
        
        # Try to get the last redirect URL if available
        if hasattr(e, 'response') and e.response is not None:
            expanded_url = e.response.url
            logger.debug(f"Last redirect URL from response: {expanded_url}")
            return expanded_url
            
        if hasattr(e, 'request'):
            last_redirected_url = e.request.url
            logger.debug(f"Last redirect URL from request: {last_redirected_url}")
            return last_redirected_url
            
        # Attempt HTTP if HTTPS failed
        if url.startswith("https://"):
            fallback_url = url.replace("https://", "http://", 1)
            logger.debug(f"Retrying with HTTP: {fallback_url}")
            try:
                response = session.head(fallback_url, allow_redirects=True, timeout=timeout)
                expanded_url = response.url
                logger.debug(f"Successfully expanded URL with HTTP: {expanded_url}")
                return expanded_url
            except requests.RequestException as e2:
                logger.warning(f"Failed to expand with HTTP fallback: {e2}")
                
                # Attempt to return the last successful redirection URL if available
                if hasattr(e2, 'response') and e2.response is not None:
                    return e2.response.url
                if hasattr(e2, 'request'):
                    return e2.request.url
    
    # Return the original URL if expansion fails
    return url

def batch_expand_urls(urls, delay=0.5):
    """
    Expand a batch of shortened URLs to their final destinations.
    
    Args:
        urls (list): List of URL dictionaries
        delay (float): Delay between requests in seconds
        
    Returns:
        list: List of URL dictionaries with expanded URLs
    """
    if not urls:
        return urls
    
    logger.debug(f"Batch expanding {len(urls)} URLs")
    
    expanded_urls = []
    for url_obj in urls:
        logger.debug(f"Processing URL in batch_expand: {url_obj}")
        
        if isinstance(url_obj, dict) and "original_url" in url_obj:
            # Clone the URL object
            expanded_url_obj = url_obj.copy()
            
            # Only expand if it's a shortened URL
            if expanded_url_obj.get("is_shortened", False):
                # Expand the URL
                expanded_url = expand_url(expanded_url_obj["original_url"])
                
                # Only set expanded_url if it's actually different from the original
                if expanded_url and expanded_url != expanded_url_obj["original_url"]:
                    expanded_url_obj["expanded_url"] = expanded_url
                    logger.debug(f"Expanded shortened URL to: {expanded_url}")
                else:
                    # If expansion failed or returned the same URL, set to "Not Applicable"
                    expanded_url_obj["expanded_url"] = "Not Applicable"
                    logger.debug(f"URL expansion failed or returned same URL, setting expanded_url to Not Applicable")
            else:
                # Explicitly set expanded_url to "Not Applicable" for non-shortened URLs
                expanded_url_obj["expanded_url"] = "Not Applicable"
                logger.debug(f"URL is not shortened, setting expanded_url to Not Applicable")
            
            expanded_urls.append(expanded_url_obj)
            
            # Add delay to avoid rate limiting
            if delay > 0 and expanded_url_obj.get("is_shortened", False):
                time.sleep(delay)
        else:
            # If not in expected format, keep as is
            expanded_urls.append(url_obj)
    
    logger.debug(f"Completed batch URL expansion")
    return expanded_urls

def process_urls(urls):
    """
    Process a list of URLs consistently to deduplicate, decode SafeLinks/Proofpoint,
    and identify shortened URLs.
    
    Args:
        urls (list): List of URL strings or dictionaries
        
    Returns:
        list: Processed URL dictionaries
    """
    if not urls:
        return []
        
    logger.debug(f"Processing {len(urls)} URLs")
    processed_urls = []
    seen_urls = set()
    
    for url in urls:
        url_str = url if isinstance(url, str) else url.get("original_url", "")
        
        if not url_str:
            continue
            
        # Skip if we've seen this URL already
        if url_str in seen_urls:
            continue

        # Skip image URLs
        if is_image_url(url_str):
            logger.debug(f"Skipping image URL: {url_str}")
            continue
        
        # Handle Microsoft SafeLinks
        if "safelinks.protection.outlook.com" in url_str:
            decoded_url = decode_safelinks(url_str)
            logger.debug(f"Decoded SafeLink: {url_str} -> {decoded_url}")
            # Skip if we've already seen this decoded URL
            if decoded_url in seen_urls:
                continue
            url_str = decoded_url
        
        # Handle Proofpoint URL Defense
        elif "urldefense.com" in url_str:
            decoded_url = decode_proofpoint_urls(url_str)
            logger.debug(f"Decoded Proofpoint URL: {url_str} -> {decoded_url}")
            # Skip if we've already seen this decoded URL
            if decoded_url in seen_urls:
                continue
            url_str = decoded_url
        
        seen_urls.add(url_str)
        
        # Standardize URL format
        url_obj = {"original_url": url_str}
        if isinstance(url, dict):
            # Only update with relevant fields to avoid carrying over inconsistent data
            if "is_shortened" in url:
                url_obj["is_shortened"] = url["is_shortened"]
            if "expanded_url" in url and url["expanded_url"] != url_str:
                url_obj["expanded_url"] = url["expanded_url"]
        
        # Check if it's a shortened URL if not already determined
        if "is_shortened" not in url_obj:
            url_obj["is_shortened"] = is_url_shortened(url_str)
        
        # Set expanded_url based on shortened status
        if not url_obj["is_shortened"]:
            url_obj["expanded_url"] = "Not Applicable"
        elif "expanded_url" not in url_obj:
            url_obj["expanded_url"] = url_str
        
        processed_urls.append(url_obj)
    
    return processed_urls

def dedupe_to_base_urls(url_list):
    """
    Deduplicate only non-shortened URLs by their base domain,
    preserving all fields including expanded_url.
    Shortened URLs are left intact.
    """
    logger.debug(f"Deduplicating {len(url_list)} URLs")

    seen_bases = set()
    deduped = []

    for url_obj in url_list:
        if not isinstance(url_obj, dict) or "original_url" not in url_obj:
            continue

        if url_obj.get("is_shortened", False):
            deduped.append(url_obj)
            continue

        try:
            parsed = urllib.parse.urlparse(url_obj["original_url"])
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if base_url not in seen_bases:
                seen_bases.add(base_url)
                deduped.append({
                    "original_url": base_url,
                    "is_shortened": False,
                    "expanded_url": url_obj.get("expanded_url", "Not Applicable")
                })
        except Exception as e:
            logger.warning(f"Error deduplicating URL {url_obj['original_url']}: {str(e)}")
            deduped.append(url_obj)

    logger.debug(f"Final deduplicated URL count: {len(deduped)}")
    return deduped

def fix_url_expansions(urls):
    """
    Fix URL expansion fields to ensure expanded_url is only set for shortened URLs.
    
    Args:
        urls (list): List of URL dictionaries
        
    Returns:
        list: List of fixed URL dictionaries
    """
    fixed_urls = []
    for url in urls:
        if isinstance(url, dict):
            # Make a copy to avoid modifying the original
            fixed_url = url.copy()
            
            # If not a shortened URL, set expanded_url to "Not Applicable"
            if not fixed_url.get("is_shortened", False):
                # Only update if it was previously set to a placeholder or the same as original
                if fixed_url.get("expanded_url") in [None, "", "Not Applicable", fixed_url.get("original_url")]:
                    fixed_url["expanded_url"] = "Not Applicable"
            # If it is shortened but expanded_url is the same as original_url, set to "Not Applicable"
            elif fixed_url.get("expanded_url") == fixed_url.get("original_url"):
                fixed_url["expanded_url"] = "Not Applicable"
                
            fixed_urls.append(fixed_url)
        else:
            fixed_urls.append(url)
    
    return fixed_urls

def extract_all_urls_from_email(body_data, body_text=""):
    """
    Extract all URLs from different parts of an email.
    
    Args:
        body_data (dict): The body data dictionary from extract_body()
        body_text (str, optional): Plain text body if already extracted
        
    Returns:
        list: List of all extracted URLs
    """
    all_urls = []
    
    # Extract URLs from HTML content if available
    if "html" in body_data and body_data["html"]:
        html_content = body_data["html"]
        # First decode any quoted-printable encoding in HTML
        decoded_html = decode_quoted_printable(html_content)
        
        # Extract URLs directly from HTML elements
        html_urls_extracted = extract_urls_from_html(decoded_html)
        logger.debug(f"Extracted {len(html_urls_extracted)} URLs directly from HTML")
        all_urls.extend(html_urls_extracted)
        
        # Also use the regular URL extractor on HTML content
        html_urls = extract_urls(decoded_html)
        logger.debug(f"Extracted {len(html_urls)} URLs from HTML with regex")
        all_urls.extend(html_urls)
    
    # Extract from plain text body
    if not body_text and "body" in body_data:
        body_text = body_data.get("body", "")
    
    if body_text:
        decoded_body = decode_quoted_printable(body_text)
        body_urls = extract_urls(decoded_body)
        logger.debug(f"Extracted {len(body_urls)} URLs from plain text body")
        all_urls.extend(body_urls)
    
    return all_urls

def extract_urls_from_attachments(attachments):
    """
    Extract URLs from email attachments.
    
    Args:
        attachments (list): List of attachment dictionaries
        
    Returns:
        list: List of URLs found in attachments
    """
    attachment_urls = []
    
    for attachment in attachments:
        if "urls" in attachment:
            attachment_urls.extend(attachment["urls"])
            # Remove the URLs from the attachment to prevent duplication
            del attachment["urls"]
    
    logger.debug(f"Extracted {len(attachment_urls)} URLs from attachments")
    return attachment_urls

def is_image_url(url):
    """
    Determines if a URL points to an image based on its extension.

    Args:
        url (str): URL to check
        
    Returns:
        bool: True if URL points to an image, False otherwise
    """
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        logger.debug("Checking and removing urls for images")
        return any(path.endswith(ext) for ext in image_extensions)
    except Exception:
        return False