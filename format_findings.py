import json

# Load the Slither output
with open('/home/dok/thelist/3huma/repo/huma-contracts-v2/slither_output.json', 'r') as f:
    slither_output = json.load(f)

# Extract and format findings for filtering
findings = []
for detector_result in slither_output['results']['detectors']:
    for finding in detector_result['markdown']:
        # Parse the finding to extract relevant information
        lines = finding.split('\n')
        finding_type = detector_result['check']
        severity = detector_result['impact'].lower()
        location = {
            "file": lines[0].split('(')[0].strip() if lines else "",
            "line": lines[0].split('(')[1].split(')')[0].strip() if lines else ""
        }
        description = finding
        
        findings.append({
            "type": finding_type,
            "severity": severity,
            "location": location,
            "description": description
        })

# Save formatted findings to a file
with open('/home/dok/thelist/3huma/repo/huma-contracts-v2/formatted_findings.json', 'w') as f:
    json.dump(findings, f, indent=2)

print(f"Formatted {len(findings)} findings for filtering")
