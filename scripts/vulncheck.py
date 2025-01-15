import os
import json
import subprocess

# Configuration
SCANOSS_API_KEY = os.getenv('SCANOSS_API_KEY', 'txnUfW0xwF0KI1U1RW5sDSBL')  # Default API key
JSON_DIR = "./"  # Directory to search for JSON files
PURL_OUTPUT_FILE = "purls.txt"  # File to store all PURLs
TIMEOUT = 10  # Timeout for each scan in seconds


def get_json_files(directory):
    """Retrieve all JSON files from the specified directory."""
    json_files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith(".json")]
    print(f"Found {len(json_files)} JSON files in directory '{directory}'.")
    return json_files


def extract_purls_from_cyclonedx(json_file):
    """Extract PURLs from a CycloneDX JSON file."""
    purls = []
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        components = data.get("components", [])
        for component in components:
            if "purl" in component:
                purls.append(component["purl"])

        print(f"Extracted {len(purls)} PURLs from {json_file}.")
    except Exception as e:
        print(f"Error reading JSON file {json_file}: {e}")
    return purls


def save_purls_to_file(purls):
    """Save all extracted PURLs to a file."""
    with open(PURL_OUTPUT_FILE, 'w') as f:
        for purl in purls:
            f.write(purl + "\n")
    print(f"Saved {len(purls)} PURLs to {PURL_OUTPUT_FILE}.")


def scan_purl(purl):
    """Scan a single PURL for vulnerabilities."""
    command = ["scanoss-py", "comp", "vu", "--purl", purl, "--key", SCANOSS_API_KEY]
    try:
        print(f"Scanning PURL: {purl}")
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=TIMEOUT)
        print(f"Results for {purl}:\n{result.stdout}")
    except subprocess.TimeoutExpired:
        print(f"Timeout: Scan for {purl} took too long and was skipped.")
    except subprocess.CalledProcessError as e:
        print(f"Error scanning PURL {purl}: {e.stderr}")


def main():
    """Main function to parse JSON files and scan PURLs."""
    json_files = get_json_files(JSON_DIR)
    all_purls = []

    for json_file in json_files:
        purls = extract_purls_from_cyclonedx(json_file)
        all_purls.extend(purls)

    # Save PURLs to a file
    save_purls_to_file(all_purls)

    # Scan each PURL for vulnerabilities
    for purl in all_purls:
        scan_purl(purl)

    print(f"Finished scanning {len(all_purls)} PURLs from {len(json_files)} JSON files.")


if __name__ == "__main__":
    main()
