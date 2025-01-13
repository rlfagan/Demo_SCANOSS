import json
import pandas as pd
import matplotlib.pyplot as plt
import os

# Load SCANOSS SBOM results from the JSON file
with open("results.json", "r") as file:
    data = json.load(file)

# Extract data
licenses = []
components = []
crypto_algorithms = []

for file_data in data.values():
    for entry in file_data:
        components.append(entry["component"])
        for license in entry.get("licenses", []):
            licenses.append(license["name"])
        for crypto in entry.get("cryptography", []):
            crypto_algorithms.append(crypto["algorithm"])

# Convert to DataFrames
license_df = pd.DataFrame({"License": licenses})
component_df = pd.DataFrame({"Component": components})
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms})

# Create a charts directory if not already present
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
