import json
from collections import Counter
from tabulate import tabulate

# Load the SCANOSS SBOM results
with open("results.json", "r") as file:
    data = json.load(file)

licenses = []
crypto_algorithms = []
components_metadata = []
provenance_data = []

# Extract data
for file_name, file_data in data.items():
    for entry in file_data:
        licenses_in_entry = entry.get("licenses", [])
        cryptos_in_entry = entry.get("cryptography", [])
        provenance = entry.get("provenance", "Unknown").strip() or "Unknown"
        provenance_data.append(provenance)

        component_name = entry.get("component", "Unknown Component")
        stars = entry.get("health", {}).get("stars", "N/A")
        forks = entry.get("health", {}).get("forks", "N/A")
        issues = entry.get("health", {}).get("issues", "N/A")
        last_updated = entry.get("health", {}).get("last_update", "N/A")
        version = entry.get("version", "N/A")
        author = entry.get("vendor", "N/A")
        license_name = licenses_in_entry[0].get("name", "Unknown License") if licenses_in_entry else "Unknown License"
        quality_score = entry.get("quality", [{}])[0].get("score", "N/A")

        # Collect component metadata
        components_metadata.append({
            "Component": component_name,
            "Stars": stars,
            "Forks": forks,
            "Issues": issues,
            "Last Updated": last_updated,
            "Provenance": provenance,
            "Version": version,
            "Author": author,
            "License": license_name,
            "Quality Score": quality_score
        })

        # Collect license and cryptographic algorithm data
        for license_info in licenses_in_entry:
            licenses.append(license_info.get("name", "Unknown License"))
        for crypto_info in cryptos_in_entry:
            crypto_algorithms.append(crypto_info.get("algorithm", "Unknown Algorithm"))

# Create summaries
license_summary = Counter(licenses).most_common(10)
crypto_summary = Counter(crypto_algorithms).most_common(10)
provenance_summary = Counter(provenance_data).items()

# Format as Markdown
license_md = tabulate(license_summary, headers=["License", "Count"], tablefmt="github")
crypto_md = tabulate(crypto_summary, headers=["Algorithm", "Count"], tablefmt="github")
components_md = tabulate(components_metadata, headers="keys", tablefmt="github")

# Generate Markdown report
with open("summary.md", "w") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write("## License Distribution (Top 10)\n")
    f.write(license_md + "\n\n")
    f.write("## Cryptographic Algorithm Usage (Top 10)\n")
    f.write(crypto_md if crypto_summary else "No cryptographic data available.\n")
    f.write("\n\n## Repository Component Metadata\n")
    f.write(components_md + "\n\n")
    f.write("### Provenance Summary:\n")
    f.write("\n".join([f"- **{country}**: {count} components" for country, count in provenance_summary]) + "\n\n")
    f.write("## Notes:\n- No vulnerabilities detected.\n- Full SBOM details are available in the uploaded artifact.\n")

print("Text-only dashboard summary generated successfully.")
