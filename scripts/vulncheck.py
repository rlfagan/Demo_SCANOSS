import os
import json
from pathlib import Path
from tabulate import tabulate

# Function to determine if a file is SPDX or CycloneDX
def is_valid_sbom(file_path):
    try:
        with open(file_path, "r") as file:
            content = json.load(file)
        # Check for CycloneDX or SPDX-specific fields
        if "bomFormat" in content and content["bomFormat"].lower() == "cyclonedx":
            return "cyclonedx"
        elif "spdxVersion" in content:
            return "spdx"
        else:
            return None
    except (json.JSONDecodeError, KeyError):
        return None  # Invalid or non-SBOM file

# Function to process vulnerabilities in SBOM files
def process_vulnerabilities(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    vulnerabilities = []

    if "components" in data:  # CycloneDX format
        for component in data["components"]:
            if "vulnerabilities" in component:
                for vuln in component["vulnerabilities"]:
                    vulnerabilities.append({
                        "File": file_path,
                        "Component": component.get("name", "Unknown Component"),
                        "Version": component.get("version", "N/A"),
                        "CVE ID": vuln.get("id", "Unknown CVE"),
                        "Severity": vuln.get("ratings", [{}])[0].get("severity", "Unknown"),
                        "Description": vuln.get("description", "No description available."),
                        "Recommendation": vuln.get("recommendation", "No recommendation available."),
                        "Source": vuln.get("source", {}).get("name", "Unknown Source"),
                        "Link": vuln.get("source", {}).get("url", "No URL provided"),
                    })

    return vulnerabilities

# Function to scan files in the repository
def scan_repo_for_vulnerabilities(repo_path):
    all_vulnerabilities = []

    for root, _, files in os.walk(repo_path):
        for file_name in files:
            if file_name.endswith((".json", ".spdx")):
                file_path = os.path.join(root, file_name)
                sbom_type = is_valid_sbom(file_path)
                if sbom_type:
                    print(f"Processing {sbom_type.upper()} SBOM: {file_path}")
                    vulnerabilities = process_vulnerabilities(file_path)
                    if vulnerabilities:
                        all_vulnerabilities.extend(vulnerabilities)
                else:
                    print(f"Skipping invalid SBOM or non-SBOM file: {file_path}")

    return all_vulnerabilities

# Generate Markdown report
def generate_vulnerability_report(vulnerabilities, output_file="vulnerabilities_summary.md"):
    if vulnerabilities:
        headers = ["File", "Component", "Version", "CVE ID", "Severity", "Description", "Recommendation", "Source", "Link"]
        vulnerability_table = tabulate(vulnerabilities, headers=headers, tablefmt="github")

        with open(output_file, "w") as report:
            report.write("# SBOM Vulnerabilities Report 📋\n\n")
            report.write("## Identified Vulnerabilities\n\n")
            report.write(vulnerability_table + "\n")
    else:
        with open(output_file, "w") as report:
            report.write("# SBOM Vulnerabilities Report 📋\n\n")
            report.write("No vulnerabilities were detected.\n")

    print(f"Vulnerability report generated: {output_file}")

# Run the script
if __name__ == "__main__":
    repo_path = Path(".")  # Current directory
    vulnerabilities = scan_repo_for_vulnerabilities(repo_path)
    generate_vulnerability_report(vulnerabilities)
