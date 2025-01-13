import json
import pandas as pd
import matplotlib.pyplot as plt
import os

# Load the SCANOSS SBOM results
with open("results.json", "r") as file:
    data = json.load(file)

licenses = []
components = []
crypto_algorithms = []

for file_data in data.values():
    for entry in file_data:
        # Handle missing keys with .get()
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
license_df["License"].value_counts().plot(kind="bar", color="steelblue")
plt.title("License Distribution")
plt.xlabel("License Type")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("charts/license_distribution.png")

# Component Usage Chart
plt.figure(figsize=(8, 5))
component_df["Component"].value_counts().plot(kind="bar", color="skyblue")
plt.title("Component Usage")
plt.xlabel("Component Name")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("charts/component_distribution.png")

# Cryptographic Algorithms Chart
plt.figure(figsize=(8, 5))
crypto_df["Algorithm"].value_counts().plot(kind="bar", color="orange")
plt.title("Cryptographic Algorithm Usage")
plt.xlabel("Algorithm")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("charts/crypto_algorithm_usage.png")

print("Charts saved successfully in the 'charts/' directory.")
