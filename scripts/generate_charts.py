import json
import pandas as pd
from collections import Counter
from tabulate import tabulate

# Load SBOM files
with open("sbom.json", "r") as f1, open("project.sbom.json", "r") as f2:
    sbom_data = json.load(f1)
    project_data = json.load(f2)

# Encryption and CVE lists
crypto_algorithms = []
cve_details = []

# Scan components in both SBOMs
for sbom in [sbom_data, project_data]:
    for component in sbom.get("components", []):
        # Cryptographic algorithms
        if "cryptography" in component:
            for crypto in component["cryptography"]:
                algo = crypto.get("algorithm", "Unknown Algorithm")
                strength = crypto.get("strength", "Unknown Strength")
                crypto_algorithms.append(f"{algo} ({strength}-bit)")

        # Vulnerabilities
        if "vulnerabilities" in component:
            for vuln in component["vulnerabilities"]:
                cve_id = vuln.get("id", "Unknown CVE")
                description = vuln.get("description", "No description provided.")
                score = vuln.get("ratings", [{}])[0].get("score", "N/A")
                severity = vuln.get("ratings", [{}])[0].get("severity", "Unknown")
                recommendation = vuln.get("recommendation", "No recommendation provided.")
                cve_details.append({
                    "CVE ID": cve_id,
                    "Severity": severity,
                    "Score": score,
                    "Description": description,
                    "Recommendation": recommendation
                })

# Generate encryption algorithm summary
crypto_summary = Counter(crypto_algorithms).items()
crypto_md = tabulate(crypto_summary, headers=["Algorithm", "Count"], tablefmt="github")

# Generate CVE summary
cve_df = pd.DataFrame(cve_details)
if not cve_df.empty:
    cve_md = tabulate(cve_df.head(10), headers="keys", tablefmt="github")
else:
    cve_md = "No CVEs found."

# Generate Markdown report
with open("summary.md", "w") as f:
    f.write("# SBOM Analysis Report 📊\n\n")
    f.write("## Cryptographic Algorithm Usage\n")
    f.write(crypto_md + "\n\n")
    f.write("## Vulnerabilities (Top 10)\n")
    f.write(cve_md + "\n\n")
    f.write("## Notes:\n")
    f.write("- Full SBOM details are available in the uploaded artifacts.\n")
    f.write("- Ensure that recommendations for CVEs are followed to mitigate security risks.\n")

print("SBOM analysis report generated successfully.")
