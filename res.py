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

# Pie Chart Function
def create_pie_chart(df, column, title, output_path, top_n=5):
    if not df.empty:
        data = df[column].value_counts().head(top_n)
        labels = data.index
        sizes = data.values

        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired.colors)
        plt.title(title)
        plt.savefig(output_path)
        plt.close()
    else:
        print(f"No data available for {title}")

# Generate pie charts
create_pie_chart(license_df, "License", "License Distribution", "charts/license_distribution.png")
create_pie_chart(component_df, "Component", "Component Usage", "charts/component_distribution.png")
create_pie_chart(crypto_df, "Algorithm", "Cryptographic Algorithm Usage", "charts/crypto_algorithm_usage.png")

# Base64-encode images for embedding in Markdown
license_chart_base64 = encode_image_to_base64("charts/license_distribution.png")
component_chart_base64 = encode_image_to_base64("charts/component_distribution.png")
crypto_chart_base64 = encode_image_to_base64("charts/crypto_algorithm_usage.png")

# Generate Summary Markdown
with open("summary.md", "w") as f:
    f.write("## SCANOSS SBOM Report 📊\n")

    # License Distribution
    f.write("### License Distribution\n")
    f.write(f"![License Distribution](data:image/png;base64,{license_chart_base64})\n")

    # Component Usage
    f.write("### Component Usage\n")
    f.write(f"![Component Usage](data:image/png;base64,{component_chart_base64})\n")

    # Cryptographic Algorithm Usage
    f.write("### Cryptographic Algorithm Usage\n")
    f.write(f"![Cryptographic Algorithm Usage](data:image/png;base64,{crypto_chart_base64})\n")

print("Pie charts and summary generated successfully.")
