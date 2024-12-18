import requests
import yaml

# URL to fetch the file
url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/Indexes/windows-index.yaml"

# Fetch the file content
response = requests.get(url)
response.raise_for_status()

# Load YAML content from response (keeping everything in memory)
yaml_content = yaml.safe_load(response.text)

# Dictionary to store categories and techniques
category_techniques = {}

# Iterate through the YAML structure to extract categories and techniques
for category, techniques in yaml_content.items():
    for technique_code, technique_data in techniques.items():
        if technique_code.startswith("T"):
            if category not in category_techniques:
                category_techniques[category] = []
            category_techniques[category].append(technique_code)

# Print the extracted categories and techniques
for category, techniques in category_techniques.items():
    print(f"{category}: {', '.join(techniques)}")
