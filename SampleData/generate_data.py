import csv
import random
from faker import Faker

fake = Faker()

# Read and parse the dummy summary/remediation entries
with open("dummy_entries.txt", "r") as f:
    content = f.read()

entries = [entry.strip() for entry in content.split("\n\n") if entry.strip()]

def parse_entry(entry):
    # Split entry into summary and remediation parts
    if "Remediation:" in entry:
        summary_part, remediation_part = entry.split("Remediation:", 1)
        # Optionally remove additional info if present
        remediation_part = remediation_part.split("AdditionalInformation:")[0].strip()
    else:
        summary_part, remediation_part = entry, ""
    # Remove leading labels
    summary_part = summary_part.replace("Summary:", "", 1).strip()
    return summary_part, remediation_part

parsed_entries = [parse_entry(entry) for entry in entries]

headers = [
    "Number", "Assignment Group", "Assignment Group Vendor", "CMS Associated Service Name",
    "CMS Reporting Sector", "CMS Sector", "CMS Service Area", "IP Address", "CMDB CI",
    "CI Class", "OS", "RPM Is DMZ", "Vulnerability", "App and Tech", "Category",
    "RPM Vulnerability Software Group", "Summary", "Remediation Note", "Proof",
    "Last Opened", "RPM Age Since Open in Days", "Age", "RPM - Load Time Debt/Influx",
    "RPM EOM Debt/Influx", "RPM - OLA Priority", "Key Critical Server Flag",
    "RPM Exploit", "Port", "Last Found", "Sys Created on", "Sys Updated On", "Load Datetime"
]

assignment_groups = ["Network Ops", "Server Ops", "Security", "DevOps"]
vendors = ["VendorA", "VendorB", "VendorC"]
reporting_sectors = ["Public", "Private", "Hybrid"]
cms_sectors = ["IT", "Finance", "HR"]
service_areas = ["Cloud", "On-Prem", "Hybrid"]
ci_classes = ["Server", "Router", "Switch", "Workstation"]
oses = ["Windows Server 2016", "Ubuntu 20.04", "CentOS 7", "Red Hat Enterprise Linux 8"]
ola_priorities = ["High", "Medium", "Low"]

num_rows = 250000

with open("dummy_data.csv", "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()
    
    for i in range(1, num_rows + 1):
        print(f"Generating row {i} of {num_rows}")
        summary_text, remediation_text = random.choice(parsed_entries)
        row = {
            "Number": i,
            "Assignment Group": random.choice(assignment_groups),
            "Assignment Group Vendor": random.choice(vendors),
            "CMS Associated Service Name": f"Service_{fake.word()}",
            "CMS Reporting Sector": random.choice(reporting_sectors),
            "CMS Sector": random.choice(cms_sectors),
            "CMS Service Area": random.choice(service_areas),
            "IP Address": fake.ipv4(),
            "CMDB CI": f"CI-{i:03d}",
            "CI Class": random.choice(ci_classes),
            "OS": random.choice(oses),
            "RPM Is DMZ": random.choice(["Yes", "No"]),
            "Vulnerability": f"CVE-2021-{random.randint(1000,100000)}",
            "App and Tech": f"{fake.word().capitalize()}App - {fake.word().capitalize()}Tech",
            "Category": random.choice(["Critical", "Non-Critical", "Warning"]),
            "RPM Vulnerability Software Group": f"Group_{random.randint(1,5)}",
            "Summary": summary_text,
            "Remediation Note": remediation_text,
            "Proof": fake.sentence(),
            "Last Opened": fake.date_this_decade().isoformat(),
            "RPM Age Since Open in Days": random.randint(0, 365),
            "Age": random.randint(1, 1000),
            "RPM - Load Time Debt/Influx": round(random.uniform(0, 1000), 2),
            "RPM EOM Debt/Influx": round(random.uniform(0, 1000), 2),
            "RPM - OLA Priority": random.choice(ola_priorities),
            "Key Critical Server Flag": random.choice(["Yes", "No"]),
            "RPM Exploit": random.choice(["True", "False"]),
            "Port": random.randint(1, 65535),
            "Last Found": fake.date_this_decade().isoformat(),
            "Sys Created on": fake.date_between(start_date="-2y", end_date="today").isoformat(),
            "Sys Updated On": fake.date_between(start_date="-1y", end_date="today").isoformat(),
            "Load Datetime": fake.date_time_this_year().isoformat(sep=" ")
        }
        writer.writerow(row)
