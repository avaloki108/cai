import os
import json

def find_solidity_files(directory):
    """Recursively find all Solidity files in a directory."""
    solidity_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sol'):
                solidity_files.append(os.path.join(root, file))
    return solidity_files

def list_directory_structure(directory, max_depth=3):
    """List the directory structure up to a certain depth."""
    structure = {}
    def traverse(current_dir, current_depth):
        if current_depth > max_depth:
            return "[Truncated]"
        items = {"files": [], "dirs": {}}
        try:
            for item in os.listdir(current_dir):
                item_path = os.path.join(current_dir, item)
                if os.path.isfile(item_path):
                    items["files"].append(item)
                elif os.path.isdir(item_path):
                    items["dirs"][item] = traverse(item_path, current_depth + 1)
        except PermissionError:
            return "[Permission Denied]"
        return items
    return traverse(directory, 0)

# Analyze the repository structure
repo_path = "/home/dok/thelist/3huma"
print("Repository Structure:")
structure = list_directory_structure(repo_path)
print(json.dumps(structure, indent=2))

# Find all Solidity files
solidity_files = find_solidity_files(repo_path)
print("\nSolidity Files Found:")
for file in solidity_files:
    print(f"  - {file}")

print(f"\nTotal Solidity files: {len(solidity_files)}")
