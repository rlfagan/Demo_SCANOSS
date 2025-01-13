import json
import pandas as pd
import os
from tabulate import tabulate

# Load SCANOSS SBOM results
with open("results.json", "r") as file:
    data = json.load(file)

licenses = []
components = []
crypto_algorithms = []
quality_scores = []
repo_health = []
copyrights = []

# Extract relevant data
for file_data in data.values():
    for entry in file_data:
        licenses_in_entry = entry.get("licenses", [])
        cryptos_in_entry = entry.get("cryptography", [])
        health = entry.get("health", {})
        copyright_text = entry.get("copyright", "No copyright info")

        components.append(entry.get("component", "Unknown Component"))
        for license_info in licenses_in_entry:
            licenses.append(license_info.get("name", "Unknown License"))
        for crypto_info in cryptos_in_entry:
            crypto_algorithms.append(crypto_info.get("algorithm", "Unknown Algorithm"))
        quality_scores.append(entry.get("quality", [{"score": "N/A"}])[0].get("score", "N/A"))
        repo_health.append({
            "Component": entry.get("component", "Unknown Component"),
            "Stars": health.get("stars", "N/A"),
            "Forks": health.get("forks", "N/A"),
            "Issues": health.get("issues", "N/A"),
            "Last Updated": health.get("last_commit_date", "N/A")
        })
        copyrights.append(copyright_text)

# Create DataFrames
license_df = pd.DataFrame({"License": licenses})
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms})
quality_df = pd.DataFrame({"Quality Score": quality_scores})
health_df = pd.DataFrame(repo_health)

# Summary Data
license_summary = license_df["License"].value_counts().head(10).reset_index().values
crypto_summary = crypto_df["Algorithm"].value_counts().head(10).reset_index().values
quality_summary = quality_df["Quality Score"].value_counts().sort_index().reset_index().values

# Repository Health Table
health_table_md = tabulate(health_df.drop_duplicates().head(10), headers="keys", tablefmt="github")

# Copyrights Table
copyrights_df = pd.DataFrame({"Copyrights": copyrights})
copyrights_md = tabulate(copyrights_df.head(10), headers="keys", tablefmt="github")

# Generate Markdown Summary
with open("summary.md", "w") as f:
    f.write("## SCANOSS SBOM Dashboard 📊\n")

    # License Summary Table
    f.write("### License Distribution (Top 10)\n")
    f.write(tabulate(license_summary, headers=["License", "Count"], tablefmt="github") + "\n\n")

    # Cryptographic Algorithm Summary Table
    f.write("### Cryptographic Algorithm Usage (Top 10)\n")
    f.write(tabulate(crypto_summary, headers=["Algorithm", "Count"], tablefmt="github") + "\n\n")

    # Quality Score Summary Table
    f.write("### Quality Scores (Best Practices)\n")
    f.write(tabulate(quality_summary, headers=["Score (out of 5)", "Count"], tablefmt="github") + "\n\n")

    # Repository Health Table
    f.write("### Repository Health Metrics\n")
    f.write(health_table_md + "\n\n")

    # Copyright Information
    f.write("### Sample Copyright Information\n")
    f.write(copyrights_md + "\n")

print("Text-only dashboard summary generated successfully.")
