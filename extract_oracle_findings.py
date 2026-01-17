#!/usr/bin/env python3
import json

# Load the Slither results
with open('slither_results.json', 'r') as f:
    results = json.load(f)

# Extract all findings
detectors = results.get('results', {}).get('detectors', [])

# Filter findings related to oracles, price integrity, and external data
oracle_findings = []
for detector in detectors:
    detector_name = detector.get('check', 'Unknown')
    elements = detector.get('elements', [])
    
    for element in elements:
        # Check if the finding is related to oracles, price, or external data
        if any(keyword in detector_name.lower() for keyword in ['oracle', 'price', 'external', 'data', 'reentrancy', 'timestamp']):
            oracle_findings.append({
                'detector': detector_name,
                'element': element.get('name', 'Unknown'),
                'type': element.get('type', 'Unknown'),
                'description': detector.get('description', 'No description'),
                'file': element.get('source_mapping', {}).get('filename_relative', 'Unknown')
            })

# Print the findings
print("Oracle/Price Integrity Findings:")
print("=" * 80)
for finding in oracle_findings:
    print(f"Detector: {finding['detector']}")
    print(f"Element: {finding['element']}")
    print(f"Type: {finding['type']}")
    print(f"File: {finding['file']}")
    print(f"Description: {finding['description']}")
    print("-" * 80)

print(f"\nTotal Oracle/Price Integrity Findings: {len(oracle_findings)}")
