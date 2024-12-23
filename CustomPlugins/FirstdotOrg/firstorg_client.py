import requests
import argparse

def query_epss(cve):
    # Define the API endpoint and parameters
    base_url = "https://api.first.org/data/v1/epss"
    params = {
        "cve": cve,
        "pretty": True  # Optional: Makes the response more readable
    }

    # Make the GET request
    response = requests.get(base_url, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        print("Response Data:", data)
    else:
        print(f"Error: {response.status_code}, {response.text}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Query the FIRST API for EPSS data of a given CVE ID.")
    parser.add_argument("cve", type=str, help="The CVE ID to query (e.g., CVE-2014-9222).")

    # Parse the arguments
    args = parser.parse_args()

    # Query the EPSS API with the provided CVE
    query_epss(args.cve)

if __name__ == "__main__":
    main()
