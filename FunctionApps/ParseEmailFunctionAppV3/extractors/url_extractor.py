import logging
import re
import urllib.parse

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
    
    logging.debug("Extracting URLs from text content")
    
    # Regular expression for URL extraction
    # This pattern matches most common URL formats
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|mailto:[^\s<>"\']+'
    
    try:
        # Find all URL matches
        url_matches = re.findall(url_pattern, text)
        
        # Process each URL
        urls = []
        for url in url_matches:
            # Add www prefix if needed
            if url.startswith('www.'):
                url = 'http://' + url
            
            # Clean the URL (remove trailing punctuation etc.)
            url = clean_url(url)
            
            # Check if it's a shortened URL
            is_shortened = is_url_shortened(url)
            
            url_info = {
                "original_url": url,
                "is_shortened": is_shortened,
                "expanded_url": url,  # Default to original, would be expanded with url_expander
                "from_original_phishing": False  # Default, would be set by caller
            }
            
            urls.append(url_info)
        
        logging.debug(f"Extracted {len(urls)} URLs")
        return urls
        
    except Exception as e:
        logging.error(f"Error extracting URLs: {str(e)}")
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
        logging.warning(f"Error normalizing URL {url}: {str(e)}")
    
    return url

def is_url_shortened(url):
    """
    Check if a URL is likely to be shortened.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if it's likely a shortened URL, False otherwise
    """
    # List of common URL shorteners
    shorteners = ["bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly", "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in", "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id", "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at", "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im", "x.co", "d.pr", "rb.gy", "vk.cc", "t1p.de", "chilp.it", "ouo.io", "zi.ma", "pd.am", "hyperurl.co", "tiny.ie", "qps.ru", "l.ead.me", "shorte.st"]
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check if domain matches a known shortener
        for shortener in shorteners:
            if domain == shortener or domain.endswith('.' + shortener):
                return True
        
        # Check for suspiciously short path (like 5-8 character hash)
        if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
            return True
    
    except Exception as e:
        logging.warning(f"Error checking if URL is shortened: {str(e)}")
    
    return False