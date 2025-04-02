# extractors/url_extractor.py
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
    
    logger.debug(f"extract_urls: {text}")
    
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
    #logger.debug(f"decode_quoted_printable: {text}")
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
    #logger.debug(f"extract_urls_from_html: {content}")
    
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
    logger.debug(f"Attempting to decode SafeLink: {safelink}")
    
    try:
        if "safelinks.protection.outlook.com" not in safelink:
            return safelink
            
        # Parse the URL
        parsed_url = urllib.parse.urlparse(safelink)
        
        # Extract the URL parameter more elegantly
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
    logger.debug(f"Attempting to decode Proofpoint URL: {urldefense}")
    
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

def expand_shortened_url(url, timeout=5):
    """
    Expands a shortened URL by following redirects.
    If the final connection cannot be made, returns the last known location.
    
    Args:
        url (str): URL to expand
        timeout (int): Request timeout in seconds
        
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
                expanded_url = expand_shortened_url(expanded_url_obj["original_url"])
                
                # Only set expanded_url if it's actually different from the original
                if expanded_url and expanded_url != expanded_url_obj["original_url"]:
                    expanded_url_obj["expanded_url"] = expanded_url
                    logger.debug(f"Expanded shortened URL to: {expanded_url}")
                else:
                    # If expansion failed or returned the same URL, set to None
                    expanded_url_obj["expanded_url"] = "Not Applicable"
                    logger.debug(f"URL expansion failed or returned same URL, setting expanded_url to None")
            else:
                # Explicitly set expanded_url to None for non-shortened URLs
                expanded_url_obj["expanded_url"] = "Not Applicable"
                logger.debug(f"URL is not shortened, setting expanded_url to None")
            
            expanded_urls.append(expanded_url_obj)
            
            # Add delay to avoid rate limiting
            if delay > 0 and expanded_url_obj.get("is_shortened", False):
                time.sleep(delay)
        else:
            # If not in expected format, keep as is
            expanded_urls.append(url_obj)
    
    logger.debug(f"Completed batch URL expansion")
    return expanded_urls

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


def strip_html_tags(text):
    """
    Removes HTML tags from text.
    
    Args:
        text (str): HTML text
        
    Returns:
        str: Plain text without HTML tags
    """
    try:
        return BeautifulSoup(text, "html.parser").get_text()
    except Exception as e:
        logger.error(f"Error stripping HTML tags: {str(e)}")
        return text