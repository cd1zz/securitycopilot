# utils/text_cleaner.py
import re
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def strip_urls_and_html(text):
    if not text:
        return text

    logger.debug(f"strip_urls_and_html text before html stripping: {text}")
    # Remove HTML tags
    soup = BeautifulSoup(text, "html.parser")
    text = soup.get_text(separator=" ", strip=True)

    # Remove raw URLs
    text = re.sub(r"\bhttps?://[\w\-._~:/?#@!$&'()*+,;=%]+", "", text)
    text = re.sub(r"\bwww\.[\w\-._~:/?#@!$&'()*+,;=%]+", "", text)

    # Remove angle-bracketed URLs (e.g., <http://...>)
    text = re.sub(r"<https?://[\w\-._~:/?#@!$&'()*+,;=%]+>", "", text)

    # Remove markdown-style image or link lines
    text = re.sub(r"\[[^\]]+\]\s*<https?://[\w\-._~:/?#@!$&'()*+,;=%]+>", "", text)

    # Remove banner or tracking garbage (optional list can grow)
    noisy_markers = ["ZjQcmQRYFpfptBannerStart", "ZjQcmQRYFpfptBannerEnd"]
    for marker in noisy_markers:
        text = text.replace(marker, "")

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()
    logger.debug(f"strip_urls_and_html text after stripping: {text}")
    return text
