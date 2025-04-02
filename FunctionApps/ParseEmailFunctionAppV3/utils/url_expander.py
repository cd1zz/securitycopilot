import logging
import requests
import time

logger = logging.getLogger(__name__)

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
    
    logger.debug(f"Expanding URL: {url}")
    
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
        
        logger.debug(f"URL expanded to: {expanded_url}")
        return expanded_url
        
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout expanding URL: {url}")
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects expanding URL: {url}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error expanding URL {url}: {str(e)}")
    
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
                    # If expansion failed or returned the same URL, set to empty string
                    expanded_url_obj["expanded_url"] = "Not Applicable"
                    logger.debug(f"URL expansion failed or returned same URL, setting expanded_url to empty string")
            else:
                # Explicitly set expanded_url to empty string for non-shortened URLs
                expanded_url_obj["expanded_url"] = "Not Applicable"
                logger.debug(f"URL is not shortened, setting expanded_url to empty string")
            
            expanded_urls.append(expanded_url_obj)
            
            # Add delay to avoid rate limiting
            if delay > 0 and expanded_url_obj.get("is_shortened", False):
                time.sleep(delay)
        else:
            # If not in expected format, keep as is
            expanded_urls.append(url_obj)
    
    logger.debug(f"Completed batch URL expansion")
    return expanded_urls