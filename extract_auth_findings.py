#!/usr/bin/env python3
import json

# Load the Slither results
with open('slither_results.json', 'r') as f:
    slither_results = json.load(f)

# Extract findings related to Auth/Upgrade/Init
auth_upgrade_init_findings = []

# Iterate through detectors and elements to find relevant issues
for detector in slither_results.get('results', {}).get('detectors', []):
    for element in detector.get('elements', []):
        # Check for Auth/Upgrade/Init related issues
        if any(keyword in str(element).lower() for keyword in ['auth', 'upgrade', 'init', 'role', 'admin', 'proxy', 'delegatecall', 'initialize']):
            auth_upgrade_init_findings.append(element)

# Print the findings
print(f"Found {len(auth_upgrade_init_findings)} potential Auth/Upgrade/Init findings:")
for finding in auth_upgrade_init_findings:
    print(json.dumps(finding, indent=2))

