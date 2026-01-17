import os
import json

# List all Solidity files in the current directory
solidity_files = [f for f in os.listdir('.') if f.endswith('.sol')]
print("Solidity files found:", solidity_files)

# Check if slither_output.json exists and read it
if os.path.exists('slither_output.json'):
    with open('slither_output.json', 'r') as f:
        data = json.load(f)
        print("Existing Slither output:", json.dumps(data, indent=2))
else:
    print("No existing Slither output found.")
