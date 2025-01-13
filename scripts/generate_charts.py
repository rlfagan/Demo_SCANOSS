import json
import pandas as pd
import os
import base64
import plotly.express as px
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
component_df = pd.DataFrame({"Component": components})
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms})
quality_df = pd.DataFrame({"Quality Score": quality_scores})
health_df = pd.DataFrame(repo_health)

# Create charts directory
os.makedirs("charts", exist_ok=True)

# Function to encode image as base64
def encode_image_to_base64(filepath):
    with open(filepath, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode("utf-8")

# License Distribution Pie Chart
fig_license = px.pie(
    license_df, names='License', title='License Distribution', color_discrete_sequence=px.colors.qualitative.Pastel
)
fig_license.write_image("charts/license_distribution.png")
license_base64 = encode_image_to_base64("charts/license_distribution.png")

# Cryptographic Algorithm Usage Pie Chart
if not crypto_df.empty:
    fig_crypto = px.pie(
        crypto_df, names='Algorithm', title='Cryptographic Algorithm Usage', color_discrete_sequence=px.colors.qualitative.Safe
    )
    fig_crypto.write_image("charts/crypto_usage.png")
    crypto_base64 = encode_image_to_base64("charts/crypto_usage.png")
else:
    crypto_base64 = None

# Quality Scores Bar Chart
if not quality_df.empty:
    fig_quality = px.bar(
        quality_df["Quality Score"].value_counts().sort_index(),
        labels={'index': 'Score (out of 5)', 'value': 'Count'},
        title='Quality Scores (Best Practices)',
        color_discrete_sequence=["#AB63FA"],
    )
    fig_quality.write_image("charts/quality_scores.png")
    quality_base64 = encode_image_to_base64("charts/quality_scores.png")
else:
    quality_base64 = None

# Repository Health Table
health_table_md = tabulate(health_df.drop_duplicates().head(10), headers="keys", tablefmt="github")

# Copyrights Table
copyrights_df = pd.DataFrame({"Copyrights": copyrights})
copyrights_md = tabulate(copyrights_df.head(10), headers="keys", tablefmt="github")

# Generate Markdown Summary
with open("summary.md", "w") as f:
    f.write("## SCANOSS SBOM Dashboard 📊\n")

    # License Distribution
    f.write("### License Distribution\n")
    f.write(f"![License Distribution](data:image/png;base64,{license_base64})\n")

    # Cryptographic Algorithm Usage
    if crypto_base64:
        f.write("### Cryptographic Algorithm Usage\n")
        f.write(f"![Cryptographic Algorithm Usage](data:image/png;base64,{crypto_base64})\n")
    else:
        f.write("### Cryptographic Algorithm Usage\nNo cryptographic data available.\n")

    # Quality Scores
    if quality_base64:
        f.write("### Quality Scores (Best Practices)\n")
        f.write(f"![Quality Scores](data:image/png;base64,{quality_base64})\n")
    else:
        f.write("### Quality Scores (Best Practices)\nNo quality scores available.\n")

    # Repository Health Table
    f.write("### Repository Health Metrics\n")
    f.write(health_table_md + "\n\n")

    # Copyright Information
    f.write("### Sample Copyright Information\n")
    f.write(copyrights_md + "\n")

print("Dashboard summary generated successfully.")
