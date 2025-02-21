
import pandas as pd
import random
from datetime import datetime, timedelta
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()

def split_large_file(file_path, max_chars=64000):
    """Split a CSV file into smaller chunks, each under max_chars, including headers."""
    logger.info("Splitting file %s into chunks of %d characters", file_path, max_chars)

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # Extract headers
    headers = lines[0]
    data_lines = lines[1:]

    # Initialize chunk tracking
    current_chunk = [headers.strip()]
    current_size = len(headers)
    chunk_index = 1

    for line in data_lines:
        line_size = len(line)
        if current_size + line_size > max_chars:
            # Write the current chunk to a new file
            chunk_file_path = f"{os.path.splitext(file_path)[0]}_part{chunk_index}.csv"
            with open(chunk_file_path, 'w', encoding='utf-8') as chunk_file:
                chunk_file.write('\n'.join(current_chunk) + '\n')
            logger.info("Created chunk file: %s", chunk_file_path)

            # Start a new chunk
            chunk_index += 1
            current_chunk = [headers.strip()]  # Include headers in the new chunk
            current_size = len(headers)

        current_chunk.append(line.strip())
        current_size += line_size

    # Write the final chunk
    if current_chunk:
        chunk_file_path = f"{os.path.splitext(file_path)[0]}_part{chunk_index}.csv"
        with open(chunk_file_path, 'w', encoding='utf-8') as chunk_file:
            chunk_file.write('\n'.join(current_chunk) + '\n')
        logger.info("Created chunk file: %s", chunk_file_path)


def main():
    # File paths (update these with actual file locations)
    seed_data_file = "C:/Users/craigfreyman/aaGITHUB_REPOS/securitycopilot/SampleData/seed_vuln_data.csv"  # Replace with your seed data file
    cisa_data_file = "C:/Users/craigfreyman/aaGITHUB_REPOS/securitycopilot/SampleData/cisa_known_exploited_vulnerabilities.csv"  # Replace with your CISA CVEs file

    # Load seed and CISA data
    logger.info("Loading seed data from %s", seed_data_file)
    seed_df = pd.read_csv(seed_data_file)
    logger.info("Loaded %d rows of seed data", len(seed_df))
    
    logger.info("Loading CISA data from %s", cisa_data_file)
    cisa_df = pd.read_csv(cisa_data_file)
    logger.info("Loaded %d rows of CISA CVE data", len(cisa_df))

    # Normalize column names in CISA data
    cisa_df.columns = cisa_df.columns.str.strip().str.lower().str.replace(" ", "_")

    # Define the number of rows to generate
    num_rows = 10000
    logger.info("Preparing to generate %d rows of simulated data", num_rows)

    # Prepare new dataset
    new_data = []

    for i in range(num_rows):
        # Randomly select a seed row (IP address, etc.)
        seed_row = seed_df.sample(n=1).to_dict(orient="records")[0]
        
        # Randomly select a CISA CVE
        cisa_row = cisa_df.sample(n=1).to_dict(orient="records")[0]
        
        # Map CISA data to the target format
        new_row = {
            "id": len(new_data) + 1,
            "number": seed_row["number"],
            "assignment_group": seed_row["assignment_group"],
            "assignment_group_vendor": seed_row["assignment_group_vendor"],
            "cms_associated_service_name": seed_row["cms_associated_service_name"],
            "cms_reporting_sector": seed_row["cms_reporting_sector"],
            "cms_sector": seed_row["cms_sector"],
            "cms_service_area": seed_row["cms_service_area"],
            "ip_address": seed_row["ip_address"],
            "cmdb_ci": seed_row["cmdb_ci"],
            "ci_class": seed_row["ci_class"],
            "os": seed_row["os"],
            "is_dmz": seed_row["is_dmz"],
            "vulnerability": cisa_row["cveid"],
            "app_and_tech": f"{cisa_row['vendorproject']} {cisa_row['product']}",
            "category": cisa_row["vulnerabilityname"],
            "software_group": cisa_row["vendorproject"],
            "summary": cisa_row["shortdescription"],
            "remediation_note": cisa_row["requiredaction"],
            "proof": cisa_row["notes"],
            "last_opened": datetime.now().strftime("%Y-%m-%d"),
            "age_days": random.randint(1, 90),
            "age": random.randint(1, 90),
            "load_time_debt": random.randint(1, 10),
            "eom_debt": random.randint(1, 10),
            "ola_priority": random.choice(["High", "Medium", "Low"]),
            "is_critical_server": random.choice(["Yes", "No"]),
            "has_exploit": random.choice(["Unknown", "Yes", "No"]),
            "port": random.choice([80, 443, 22, 445, 3389]),
            "last_found": datetime.now().strftime("%Y-%m-%d"),
            "created_on": (datetime.now() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
            "updated_on": datetime.now().strftime("%Y-%m-%d"),
            "load_datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        new_data.append(new_row)
        
        # Log progress every 100 rows
        if (i + 1) % 100 == 0:
            logger.info("Generated %d/%d rows", i + 1, num_rows)

    # Create a new DataFrame
    new_df = pd.DataFrame(new_data)

    # Save to CSV
    output_file = "simulated_vuln_spreadsheet.csv"
    new_df.to_csv(output_file, index=False)

    logger.info("Data generation complete! Saved to %s", output_file)

    # Split the large file into chunks
    split_large_file(output_file, max_chars=64000)

if __name__ == "__main__":
    main()
