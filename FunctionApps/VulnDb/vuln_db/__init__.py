import logging
import json
import azure.functions as func
import requests
import time

class VulnDBClient:
    def __init__(self, client_id, client_secret, base_url="https://vulndb.flashpoint.io"):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.session = requests.Session()

    def authenticate(self):
        """Authenticate using client_id and client_secret to get a Bearer token."""
        logging.info("Authenticating with VulnDB API.")
        url = f"{self.base_url}/oauth/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
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
        logging.info("API request successful.")
        return response.json()

    def get_vulnerability_by_cve(self, cve_id):
        """Get vulnerability details by CVE ID with specific data elements."""
        logging.info(f"Fetching vulnerability details for CVE ID: {cve_id}.")
        endpoint = f"vulnerabilities/{cve_id}/find_by_cve_id"
        params = {
            "show_cvss": True,
            "show_cvss_v3": True,
            "vtem": True,
            "additional_info": False,
            "nested": False,
            "size": 1
        }
        return self._request("GET", endpoint, params=params)

async def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing HTTP trigger request.")

    try:
        # Parse request body as JSON
        try:
            req_body = req.get_json()
            logging.info("Request JSON parsed successfully.")
        except ValueError:
            logging.error("Invalid JSON payload.")
            return func.HttpResponse(
                "Invalid JSON payload.",
                status_code=400
            )

        # Extract parameters from the request
        cve_id = req_body.get('cve_id')
        client_id = req_body.get('client_id')
        client_secret = req_body.get('client_secret')

        if not all([cve_id, client_id, client_secret]):
            logging.error("Missing one or more required parameters: cve_id, client_id, client_secret.")
            return func.HttpResponse(
                "Missing one or more required parameters: cve_id, client_id, client_secret.",
                status_code=400
            )

        # Initialize and authenticate the VulnDB client
        logging.info("Initializing VulnDB client.")
        client = VulnDBClient(client_id, client_secret)
        client.authenticate()

        # Query the VulnDB API
        logging.info("Querying the VulnDB API.")
        vulnerability_response = client.get_vulnerability_by_cve(cve_id)
        results = vulnerability_response.get("results", [])

        # Extract and filter the data
        if results:
            logging.info("Processing vulnerability data.")
            result = results[0]
            filtered_data = {
                "cve_id": cve_id,
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
                "exploit_publish_date": result.get("exploit_publish_date", "N/A"),
            }
        else:
            logging.warning("No results found for the given CVE.")
            filtered_data = {
                "cve_id": cve_id,
                "title": None,
                "description": None,
                "cvss_base_score": None,
                "cvss_temporal_score": None,
                "exploit_publish_date": None,
            }

        # Return the filtered data as JSON
        logging.info("Returning filtered data.")
        return func.HttpResponse(
            json.dumps(filtered_data, indent=4),
            mimetype="application/json",
            status_code=200
        )

    except requests.RequestException as e:
        logging.error(f"Request error: {e}")
        return func.HttpResponse(
            f"Error querying VulnDB API: {e}",
            status_code=500
        )
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse(
            f"Unexpected error: {e}",
            status_code=500
        )
