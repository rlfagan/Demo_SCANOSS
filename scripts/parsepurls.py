find . -name "*.json" -exec echo "Processing {}" \; -exec jq -c '.components[]?.purl // empty | {purl: .}' {} + | jq -s '{purls: .}' > purls.json
