import os
import sys
import requests

def send_raw_email(eml_file_path, url):
    """
    Reads a .eml file and sends its raw content to the specified URL.

    Parameters:
    eml_file_path (str): Path to the .eml file.
    url (str): The endpoint to send the POST request to.
    """
    if not os.path.exists(eml_file_path):
        print(f"Error: File '{eml_file_path}' does not exist.")
        sys.exit(1)

    try:
        # Read the raw content of the .eml file
        with open(eml_file_path, 'rb') as eml_file:
            raw_email = eml_file.read()

        # Send the raw email content to the API
        response = requests.post(url, data=raw_email, headers={"Content-Type": "application/octet-stream"})

        # Print the server's response
        print("Server response:")
        print(f"Status code: {response.status_code}")
        with open('output.html', 'w') as f:
            f.write(response.text)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python send_raw_email.py <path_to_eml_file>")
        sys.exit(1)

    # Define the API URL
    api_url = " http://localhost:7071/api/json_to_html"

    # Read the .eml file path from the command line
    eml_file_path = sys.argv[1]

    # Send the raw .eml content
    send_raw_email(eml_file_path, api_url)
