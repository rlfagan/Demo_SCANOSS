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

for file_data in data.values():
    for entry in file_data:
        component = entry.get("component", "Unknown Component")
        licenses_in_entry = entry.get("licenses", [])
        cryptos_in_entry = entry.get("cryptography", [])

        components.append(component)
        for license_info in licenses_in_entry:
            licenses.append(license_info.get("name", "Unknown License"))
        for crypto_info in cryptos_in_entry:
            crypto_algorithms.append(crypto_info.get("algorithm", "Unknown Algorithm"))

# Convert to DataFrames
license_df = pd.DataFrame({"License": licenses})
component_df = pd.DataFrame({"Component": components})
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms})

# Create the charts directory
os.makedirs("charts", exist_ok=True)

# Function to encode image as base64
def encode_image_to_base64(filepath):
    with open(filepath, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode("utf-8")

# License Distribution Chart
license_chart_path = "charts/license_distribution.png"
plt.figure(figsize=(8, 5))
if not license_df.empty:
    license_df["License"].value_counts().plot(kind="bar", color="steelblue")
    plt.title("License Distribution")
    plt.xlabel("License Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(license_chart_path)
else:
    license_chart_base64 = None
    print("No license data found.")

# Component Usage Chart
component_chart_path = "charts/component_distribution.png"
plt.figure(figsize=(8, 5))
if not component_df.empty:
    component_df["Component"].value_counts().plot(kind="bar", color="skyblue")
    plt.title("Component Usage")
    plt.xlabel("Component Name")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(component_chart_path)
else:
    component_chart_base64 = None
    print("No component data found.")

# Cryptographic Algorithms Chart
crypto_chart_path = "charts/crypto_algorithm_usage.png"
plt.figure(figsize=(8, 5))
if not crypto_df.empty:
    crypto_df["Algorithm"].value_counts().plot(kind="bar", color="orange")
    plt.title("Cryptographic Algorithm Usage")
    plt.xlabel("Algorithm")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(crypto_chart_path)
else:
    crypto_chart_base64 = None
    print("No cryptographic algorithm data found.")

# Base64-encode images
license_chart_base64 = encode_image_to_base64(license_chart_path) if os.path.exists(license_chart_path) else None
component_chart_base64 = encode_image_to_base64(component_chart_path) if os.path.exists(component_chart_path) else None
crypto_chart_base64 = encode_image_to_base64(crypto_chart_path) if os.path.exists(crypto_chart_path) else None

# Generate Summary Markdown
with open("summary.md", "w") as f:
    f.write("## SCANOSS SBOM Report 📊\n")

    # License Distribution
    if license_chart_base64:
        f.write("### License Distribution\n")
        f.write(f"![License Distribution](data:image/png;base64,{license_chart_base64})\n")
    else:
        f.write("### License Distribution\nNo license data available.\n")

    # Component Usage
    if component_chart_base64:
        f.write("### Component Usage\n")
        f.write(f"![Component Usage](data:image/png;base64,{component_chart_base64})\n")
    else:
        f.write("### Component Usage\nNo component data available.\n")

    # Cryptographic Algorithm Usage
    if crypto_chart_base64:
        f.write("### Cryptographic Algorithm Usage\n")
        f.write(f"![Cryptographic Algorithm Usage](data:image/png;base64,{crypto_chart_base64})\n")
    else:
        f.write("### Cryptographic Algorithm Usage\nNo cryptographic algorithm data available.\n")

    # Summary Table
    f.write("\n### Summary Table\n")
    summary_data = {
        "Top Components": component_df["Component"].value_counts().head(5),
        "Top Licenses": license_df["License"].value_counts().head(5),
        "Top Cryptographic Algorithms": crypto_df["Algorithm"].value_counts().head(5),
    }

    for key, values in summary_data.items():
        if not values.empty:
            f.write(f"#### {key}\n")
            f.write(tabulate(values.reset_index().values, headers=[key, "Count"], tablefmt="github"))
            f.write("\n\n")
        else:
            f.write(f"#### {key}\nNo data available.\n\n")

print("Charts and summary
