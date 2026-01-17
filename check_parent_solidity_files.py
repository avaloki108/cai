import os
import json

# Check the parent directory for Solidity files
parent_dir = "../"
solidity_files = []
for root, dirs, files in os.walk(parent_dir):
    for file in files:
        if file.endswith('.sol'):
            solidity_files.append(os.path.join(root, file))

print("Solidity files found in parent directory:", solidity_files)
