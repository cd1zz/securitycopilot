import requests

def expand_url(short_url: str) -> str:
    try:
        # Perform a GET request to expand the URL, following all redirects
        response = requests.get(short_url, allow_redirects=True, timeout=10)
        # If successful, return the final URL
        return response.url
    except requests.RequestException as e:
        # If the GET request fails, log the error and attempt to manually retrieve the Location header if possible
        print(f"Error expanding URL {short_url}: {e}")
        
        try:
            # Try a HEAD request to see if we can get a Location header for redirection
            response = requests.head(short_url, allow_redirects=False, timeout=5)
            if response.status_code in range(300, 400) and 'Location' in response.headers:
                return response.headers['Location']
        except requests.RequestException as e_head:
            # Log the error and fall back to the original URL if no expansion could be done
            print(f"Error with HEAD request for URL {short_url}: {e_head}")
    
    # Return the original URL if no expansion could be determined
    return short_url

# Example usage
shortened_urls = [
    "https://t.co/asdf811",
    "https://t.co/ZA7gRRYyNY",
    "https://t.co/q1X2GlYTmH",
    "https://t.co/589Sq9jgIJ"
]

expanded_urls = [expand_url(url) for url in shortened_urls]

# Output the expanded URLs
for original, expanded in zip(shortened_urls, expanded_urls):
    print(f"Original: {original} -> Expanded: {expanded}")
