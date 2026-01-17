import json

# Load the Slither results
with open('slither_oracle_results.json', 'r') as f:
    slither_results = json.load(f)

# Extract findings
findings = []
for detector in slither_results.get('results', {}).get('detectors', []):
    for element in detector.get('elements', []):
        finding = {
            'type': detector.get('check', 'unknown'),
            'description': detector.get('description', 'No description'),
            'location': element.get('source_mapping', {}).get('filename_short', 'Unknown'),
            'severity': detector.get('impact', 'unknown')
        }
        findings.append(finding)

# Print findings
for finding in findings:
    print(f"Type: {finding['type']}")
    print(f"Description: {finding['description']}")
    print(f"Location: {finding['location']}")
    print(f"Severity: {finding['severity']}")
    print("-" * 80)
