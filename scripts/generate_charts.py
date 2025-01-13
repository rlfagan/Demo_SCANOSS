import json
import pandas as pd
import matplotlib.pyplot as plt
import os
import base64
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
            "Stars": health.get("stars", 0),
            "Forks": health.get("forks", 0),
            "Issues": health.get("issues", 0),
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

# Function to save and encode chart as base64
def save_and_encode_chart(filename, chart_func):
    chart_func()
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    with open(filename, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode("utf-8")

# License Distribution Pie Chart
def license_pie_chart():
    license_df["License"].value_counts().plot(kind="pie", autopct="%1.1f%%", startangle=90, cmap="Paired")
    plt.title("License Distribution")
    plt.ylabel("")

license_base64 = save_and_encode_chart("charts/license_distribution.png", license_pie_chart)

# Cryptographic Algorithm Usage Pie Chart
def crypto_pie_chart():
    crypto_df["Algorithm"].value_counts().plot(kind="pie", autopct="%1.1f%%", startangle=90, cmap="cool")
    plt.title("Cryptographic Algorithm Usage")
    plt.ylabel("")

crypto_base64 = save_and_encode_chart("charts/crypto_usage.png", crypto_pie_chart)

# Quality Scores Bar Chart
def quality_bar_chart():
    quality_df["Quality Score"].value_counts().sort_index().plot(kind="bar", color="purple")
    plt.title("Quality Scores (Best Practices)")
    plt.xlabel("Score (out of 5)")
    plt.ylabel("Count")

quality_base64 = save_and_encode_chart("charts/quality_scores.png", quality_bar_chart)

# Repository Health Table
health_table_md = tabulate(health_df, headers="keys", tablefmt="github")

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
    f.write("### Cryptographic Algorithm Usage\n")
    f.write(f"![Cryptographic Algorithm Usage](data:image/png;base64,{crypto_base64})\n")

    # Quality Scores
    f.write("### Quality Scores (Best Practices)\n")
    f.write(f"![Quality Scores](data:image/png;base64,{quality_base64})\n")

    # Repository Health Table
    f.write("### Repository Health Metrics\n")
    f.write(health_table_md + "\n\n")

    # Copyright Information
    f.write("### Sample Copyright Information\n")
    f.write(copyrights_md + "\n")

print("Dashboard summary generated successfully.")
