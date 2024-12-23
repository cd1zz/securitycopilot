import requests
import time
import argparse
import logging
import json
from datetime import datetime

class VulnDBClient:
    def __init__(self, client_id, client_secret, base_url="https://vulndb.flashpoint.io"):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.session = requests.Session()

    def authenticate(self):
        """Authenticate using client_id and client_secret to get a Bearer token."""
        url = f"{self.base_url}/oauth/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        logging.info("Authenticating with VulnDB API.")
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            self.token = response.json().get("access_token")
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            logging.info("Authentication successful.")
        else:
            logging.error(f"Authentication failed: {response.status_code} {response.text}")
            response.raise_for_status()

    def _request(self, method, endpoint, params=None, data=None):
        if not self.token:
            raise ValueError("Client is not authenticated. Call authenticate() first.")

        url = f"{self.base_url}/api/v2/{endpoint.strip('/')}"
        logging.info(f"Making {method} request to {url} with params: {params} and data: {data}")
        response = self.session.request(
            method=method,
            url=url,
            params=params,
            json=data
        )
        if response.status_code == 429:
            logging.warning("Rate limit reached. Retrying after a delay.")
            time.sleep(1)
            return self._request(method, endpoint, params, data)
        elif response.status_code >= 400:
            logging.error(f"API request failed: {response.status_code} {response.text}")
            response.raise_for_status()
        return response.json()

    def get_account_status(self):
        """Fetch account status information."""
        status = self._request("GET", "account_status")
        logging.info(f"Account status: {status}")
        return status

    def get_vulnerability_by_cve(self, cve_id):
        """Get vulnerability details by CVE ID with specific data elements."""
        endpoint = f"vulnerabilities/{cve_id}/find_by_cve_id"
        params = {
            "show_cvss": True,  # Include CVSS base and temporal data
            "show_cvss_v3": True,
            "vtem": True,  # Include temporal metrics
            "additional_info": False,  # Skip unnecessary additional info
            "nested": False,  # Avoid nested structures
            "size": 1  # Limit the results to only one record
        }
        return self._request("GET", endpoint, params=params)

# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    parser = argparse.ArgumentParser(description="Authenticate and interact with the VulnDB API.")
    parser.add_argument("--client_id", required=True, help="Client ID for authentication")
    parser.add_argument("--client_secret", required=True, help="Client Secret for authentication")
    parser.add_argument("--cve_id", required=True, help="CVE ID to fetch vulnerability details")
    args = parser.parse_args()

    client = VulnDBClient(client_id=args.client_id, client_secret=args.client_secret)

    # Authenticate to get a Bearer token
    client.authenticate()

    # Check and log account status
    account_status = client.get_account_status()
    api_calls_allowed = account_status.get("number_of_api_calls_allowed_per_month")
    api_calls_made = account_status.get("number_of_api_calls_made_this_month")
    logging.info(f"API Calls Allowed: {api_calls_allowed}, API Calls Made: {api_calls_made}")

    # Fetch vulnerability details by CVE ID
    vulnerability_response = client.get_vulnerability_by_cve(args.cve_id)
    results = vulnerability_response.get("results", [])
    if results:
        # Assume we're interested in the first result
        result = results[0]
        extracted_data = {
            "cve_id": args.cve_id,
            "title": result.get("title", "N/A"),
            "description": result.get("description", "N/A"),
            "cvss_base_score": (
                result.get("cvss_version_three_metrics", [{}])[0].get("calculated_cvss_base_score", "N/A")
                if result.get("cvss_version_three_metrics")
                else "N/A"
            ),
            "cvss_temporal_score": (
                result.get("cvss_version_three_metrics", [{}])[0].get("temporal_score", "N/A")
                if result.get("cvss_version_three_metrics")
                else "N/A"
            ),
            "ransomware_likelihood": result.get("ransomware_likelihood", "N/A"),
            "solution": result.get("solution", "N/A"),
            "exploit_publish_date": result.get("exploit_publish_date", "N/A")
        }
    else:
        logging.warning("No results found for the given CVE.")
        extracted_data = {
            "cve_id": args.cve_id,
            "title": None,
            "description": None,
            "cvss_base_score": None,
            "cvss_temporal_score": None,
            "ransomware_likelihood": None,
            "solution": None,
            "exploit_publish_date": None
        }


    # Write extracted data to file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{args.cve_id}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(extracted_data, f, indent=4)
    logging.info(f"Results written to {filename}")
