import json
import pandas as pd
import matplotlib.pyplot as plt
import os
from tabulate import tabulate

# Load SCANOSS SBOM results
with open("results.json", "r") as file:
    data = json.load(file)

licenses = []
components = []
crypto_algorithms = []

for file_data in data.values():
    for entry in file_data:
        # Handle missing keys gracefully
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

# License Distribution Chart
plt.figure(figsize=(8, 5))
if not license_df.empty:
    license_df["License"].value_counts().plot(kind="bar", color="steelblue")
    plt.title("License Distribution")
    plt.xlabel("License Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("charts/license_distribution.png")
else:
    print("No license data found.")

# Component Usage Chart
plt.figure(figsize=(8, 5))
if not component_df.empty:
    component_df["Component"].value_counts().plot(kind="bar", color="skyblue")
    plt.title("Component Usage")
    plt.xlabel("Component Name")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("charts/component_distribution.png")
else:
    print("No component data found.")

# Cryptographic Algorithms Chart
plt.figure(figsize=(8, 5))
if not crypto_df.empty:
    crypto_df["Algorithm"].value_counts().plot(kind="bar", color="orange")
    plt.title("Cryptographic Algorithm Usage")
    plt.xlabel("Algorithm")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("charts/crypto_algorithm_usage.png")
else:
    print("No cryptographic algorithm data found.")
    with open("summary.md", "a") as f:
        f.write("\n**Note:** No cryptographic algorithms were detected.\n")

# Generate Summary Table
summary_data = {
    "Top Components": component_df["Component"].value_counts().head(5),
    "Top Licenses": license_df["License"].value_counts().head(5),
    "Top Cryptographic Algorithms": crypto_df["Algorithm"].value_counts().head(5),
}

# Write Summary to Markdown
with open("summary.md", "w") as f:
    f.write("## SCANOSS SBOM Report 📊\n")
    if not license_df.empty:
        f.write("### License Distribution\n")
        f.write("![License Distribution](charts/license_distribution.png)\n")
    else:
        f.write("### License Distribution\nNo license data available.\n")

    if not component_df.empty:
        f.write("### Component Usage\n")
        f.write("![Component Usage](charts/component_distribution.png)\n")
    else:
        f.write("### Component Usage\nNo component data available.\n")

    if not crypto_df.empty:
        f.write("### Cryptographic Algorithm Usage\n")
        f.write("![Cryptographic Algorithm Usage](charts/crypto_algorithm_usage.png)\n")
    else:
        f.write("### Cryptographic Algorithm Usage\nNo cryptographic algorithm data available.\n")

    # Write Summary Table
    f.write("\n### Summary Table\n")
    f.write("Here is a summary of the top 5 components, licenses, and cryptographic algorithms:\n\n")
    for key, values in summary_data.items():
        if not values.empty:
            f.write(f"#### {key}\n")
            f.write(tabulate(values.reset_index().values, headers=[key, "Count"], tablefmt="github"))
            f.write("\n\n")
        else:
            f.write(f"#### {key}\nNo data available.\n\n")

print("Charts and summary generated successfully.")
