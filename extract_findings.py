import json

# Load the Slither results
with open('slither_oracle_results.json', 'r') as f:
    slither_results = json.load(f)

# Extract findings
findings = []
for result in slither_results.get('results', []):
    finding = {
        'type': result.get('check', 'unknown'),
        'description': result.get('description', 'No description'),
        'location': result.get('source_mapping', {}).get('filename', 'Unknown'),
        'severity': result.get('severity', 'unknown')
    }
    findings.append(finding)

# Print findings
for finding in findings:
    print(f"Type: {finding['type']}")
    print(f"Description: {finding['description']}")
    print(f"Location: {finding['location']}")
    print(f"Severity: {finding['severity']}")
    print("-" * 80)
