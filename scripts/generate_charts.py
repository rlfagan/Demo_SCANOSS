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
key_strengths = []
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
            key_strengths.append(crypto_info.get("strength", "N/A"))
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
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms, "Strength": key_strengths})
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

# License Distribution Bar Chart
def license_bar_chart():
    license_df["License"].value_counts().plot(kind="barh", color="skyblue")
    plt.title("License Distribution")
    plt.xlabel("Count")
    plt.ylabel("License Type")

license_base64 = save_and_encode_chart("charts/license_distribution.png", license_bar_chart)

# Cryptographic Algorithm Usage Bar Chart
def crypto_bar_chart():
    if not crypto_df.empty:
        crypto_df["Algorithm"].value_counts().plot(kind="barh", color="orange")
        plt.title("Cryptographic Algorithm Usage")
        plt.xlabel("Count")
        plt.ylabel("Algorithm")
    else:
        plt.figure(figsize=(5, 5))
        plt.text(0.5, 0.5, "No cryptographic data available", ha="center", va="center", fontsize=12)
        plt.axis("off")

crypto_base64 = save_and_encode_chart("charts/crypto_usage.png", crypto_bar_chart)

# Quality Scores Bar Chart
def quality_bar_chart():
    if not quality_df.empty:
        quality_df["Quality Score"].value_counts().sort_index().plot(kind="bar", color="purple")
        plt.title("Quality Scores (Best Practices)")
        plt.xlabel("Score (out of 5)")
        plt.ylabel("Count")
    else:
        plt.figure(figsize=(5, 5))
        plt.text(0.5, 0.5, "No quality scores available", ha="center", va="center", fontsize=12)
        plt.axis("off")

quality_base64 = save_and_encode_chart("charts/quality_scores.png", quality_bar_chart)

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
