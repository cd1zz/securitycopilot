import logging
import requests
import urllib.parse
import time

def expand_url(url, timeout=5, max_redirects=10):
    """
    Expand a shortened URL to its final destination.
    
    Args:
        url (str): URL to expand
        timeout (int): Request timeout in seconds
        max_redirects (int): Maximum number of redirects to follow
        
    Returns:
        str: Expanded URL or original URL if expansion fails
    """
    if not url:
        return url
    
    logging.debug(f"Expanding URL: {url}")
    
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    
    try:
        # Use HEAD request with no data transfer to efficiently follow redirects
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        
        # Get the final URL after redirects
        expanded_url = response.url
        
        logging.debug(f"URL expanded to: {expanded_url}")
        return expanded_url
        
    except requests.exceptions.Timeout:
        logging.warning(f"Timeout expanding URL: {url}")
    except requests.exceptions.TooManyRedirects:
        logging.warning(f"Too many redirects expanding URL: {url}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"Error expanding URL {url}: {str(e)}")
    
    # If expansion fails, return the original URL
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
    
    logging.debug(f"Batch expanding {len(urls)} URLs")
    
    expanded_urls = []
    for url_obj in urls:
        if isinstance(url_obj, dict) and "original_url" in url_obj and url_obj.get("is_shortened", False):
            # Clone the URL object
            expanded_url_obj = url_obj.copy()
            
            # Expand the URL
            expanded_url = expand_url(url_obj["original_url"])
            expanded_url_obj["expanded_url"] = expanded_url
            
            expanded_urls.append(expanded_url_obj)
            
            # Add delay to avoid rate limiting
            if delay > 0:
                time.sleep(delay)
        else:
            # If not a shortened URL or not in expected format, keep as is
            expanded_urls.append(url_obj)
    
    logging.debug(f"Completed batch URL expansion")
    return expanded_urls