import requests
import json
import logging
import sys
import argparse
from datetime import datetime
from typing import Optional, List, Dict

# Configure logging
log = logging.getLogger('vulndb')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

# Constants
VULNDB_URL = "https://vulndb.cyberriskanalytics.com"

def get_oauth_token(client_id: str, client_secret: str) -> Optional[str]:
    """Obtain an OAuth token using the client ID and secret."""
    try:
        log.info("Attempting to obtain OAuth token...")
        url = f"{VULNDB_URL}/oauth/token"
        payload = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret
        }
        response = requests.post(url, data=payload)
        response.raise_for_status()
        token_data = response.json()
        log.info("OAuth token obtained successfully.")
        return token_data.get('access_token')
    except requests.RequestException as e:
        log.error("Failed to obtain OAuth token: %s", e, exc_info=True)
        return None

def query_vulndb(vulnerability: str, token: str) -> Optional[dict]:
    """Query the VulnDB API for a given vulnerability."""
    try:
        log.info("Querying VulnDB for vulnerability: %s", vulnerability)
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{VULNDB_URL}/api/v1/vulnerabilities/{vulnerability}/find_by_cve_id"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        log.info("VulnDB query successful.")
        return response.json()
    except requests.RequestException as e:
        log.error("Error querying VulnDB: %s", e, exc_info=True)
        return None

def filter_data(data: dict) -> Dict[str, List[str]]:
    """Filter the data to retain specific fields."""
    log.info("Filtering data...")
    try:
        # Process all results instead of just the first
        filtered_results = []
        for result in data.get("results", []):
            filtered = {
                "Title": result.get("title", ""),
                "Description": result.get("description", ""),
                "Exploit Publish Date": result.get("exploit_publish_date", ""),
                "CVSS Base Score": result.get("cvss_metrics", [{}])[0].get("calculated_cvss_base_score", ""),
                "Products": sorted(set(product.get("name", "") for product in result.get("products", [])))
            }
            filtered_results.append(filtered)
        log.info("Filtering complete.")
        return filtered_results
    except Exception as e:
        log.error("Error during data filtering: %s", e, exc_info=True)
        return []

def save_to_file(filename: str, data: dict):
    """Save the query result to a JSON file."""
    try:
        log.info("Saving results to file: %s", filename)
        with open(filename, 'w') as file:
            json.dump(data, file, indent=2)
        log.info("Results saved successfully.")
    except Exception as e:
        log.error("Failed to save results to file: %s", e, exc_info=True)

def main():
    parser = argparse.ArgumentParser(description="Query VulnDB API or process a local JSON file for CVE details.")
    parser.add_argument("--client_id", help="VulnDB API Client ID")
    parser.add_argument("--client_secret", help="VulnDB API Client Secret")
    parser.add_argument("--cve_id", help="CVE ID to query")
    parser.add_argument("--file", help="Path to a local JSON file to process")

    args = parser.parse_args()

    if args.file:
        # Process a local file
        log.info("Processing local file: %s", args.file)
        try:
            with open(args.file, 'r') as file:
                data = json.load(file)
            filtered_data = filter_data(data)
            output_filename = f"filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_file(output_filename, filtered_data)
        except Exception as e:
            log.error("Failed to process file: %s", e, exc_info=True)
            sys.exit(1)
    elif args.client_id and args.client_secret and args.cve_id:
        # Authenticate to get token
        log.info("Starting API query with provided credentials.")
        token = get_oauth_token(args.client_id, args.client_secret)
        if not token:
            log.error("Failed to authenticate with VulnDB API.")
            sys.exit(1)

        # Query the API
        response_data = query_vulndb(args.cve_id, token)
        if not response_data:
            log.error("Failed to fetch details for CVE ID: %s", args.cve_id)
            sys.exit(1)

        # Save full results
        full_output_filename = f"{args.cve_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_to_file(full_output_filename, response_data)

        # Save filtered results
        filtered_data = filter_data(response_data)
        filtered_output_filename = f"filtered_{args.cve_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_to_file(filtered_output_filename, filtered_data)
    else:
        log.error("Invalid arguments. Provide either --file or --client_id, --client_secret, and --cve_id.")
        sys.exit(1)

if __name__ == "__main__":
    main()
