#!/usr/bin/env python3
import json
import sys

# Load the Slither results
with open('/tmp/slither_results.json', 'r') as f:
    slither_data = json.load(f)

# Extract critical findings
critical_findings = []

# Look for high-severity issues
if 'detectors' in slither_data['results']:
    for detector in slither_data['results']['detectors']:
        detector_name = detector.get('check', 'unknown')
        elements = detector.get('elements', [])
        
        # Filter for critical issues
        if any(keyword in detector_name.lower() for keyword in ['reentrancy', 'overflow', 'underflow', 'uninitialized', 'timestamp', 'assembly', 'incorrect']):
            for element in elements:
                finding = {
                    'detector': detector_name,
                    'type': element.get('type', 'unknown'),
                    'name': element.get('name', 'unknown'),
                    'file': element.get('source_mapping', {}).get('filename_short', 'unknown'),
                    'lines': element.get('source_mapping', {}).get('lines', [])
                }
                critical_findings.append(finding)

# Print critical findings
print(f"Found {len(critical_findings)} critical findings:")
for i, finding in enumerate(critical_findings[:10], 1):  # Show top 10
    print(f"\n{i}. {finding['detector']}")
    print(f"   Type: {finding['type']}")
    print(f"   Name: {finding['name']}")
    print(f"   File: {finding['file']}")
    print(f"   Lines: {finding['lines']}")

print(f"\nTotal critical findings: {len(critical_findings)}")
