# utils/url_utils.py
import logging
import urllib.parse

logger = logging.getLogger(__name__)

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