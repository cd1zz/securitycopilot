import requests
import json

API_KEY = ''  # Replace with your real API key
TEST_IP = '8.8.8.8'  # Example IP

url = f'https://www.ipqualityscore.com/api/json/ip/{API_KEY}/{TEST_IP}'

payload = {
    'strictness': 1,
    'user_agent': 'Mozilla/5.0',
    'user_language': 'en-US',
    'allow_public_access_points': 'true',
    'lighter_penalties': 'false'
}

response = requests.post(url, data=payload)

if response.status_code == 200:
    print(json.dumps(response.json(), indent=2))
else:
    print(f"Error {response.status_code}: {response.text}")
