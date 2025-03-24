import requests

API_KEY = ''
IP_ADDRESS = '8.8.8.8'
BASE_URL = 'https://ipqualityscore.com/api/json/ip'

headers = {
    'IPQS-KEY': API_KEY  # Custom header for API key
}

params = {
    'strictness': 1,
    'user_agent': 'Mozilla/5.0',
    'user_language': 'en-US',
    'fast': True,
    'mobile': False,
    'allow_public_access_points': True,
    'lighter_penalties': True,
    'transaction_strictness': 1
}

response = requests.get(f"{BASE_URL}/{IP_ADDRESS}", headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    print(f"Fraud Score: {data.get('fraud_score')}")
    print(f"Proxy Detected: {data.get('proxy')}")
    print(f"VPN: {data.get('vpn')}, TOR: {data.get('tor')}")
else:
    print(f"Error {response.status_code}: {response.text}")
