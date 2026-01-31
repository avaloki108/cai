
import os
import json
from pathlib import Path

repo_path = "/home/dok/thelist/3huma/repo/huma-contracts-v2"

def explore_repo(path, max_depth=3):
    """Explore repository structure"""
    structure = {}
    for root, dirs, files in os.walk(path):
        # Limit depth
        rel_path = os.path.relpath(root, path)
        depth = rel_path.count(os.sep) if rel_path != '.' else 0
        
        if depth <= max_depth:
            current_level = structure
            if rel_path != '.':
                for part in rel_path.split(os.sep):
                    current_level = current_level.setdefault(part, {})
            
            # Filter for Solidity files and relevant config
            sol_files = [f for f in files if f.endswith('.sol')]
            if sol_files:
                current_level['_files'] = sol_files
            
    return structure

print("Exploring repository structure...")
structure = explore_repo(repo_path)
print(json.dumps(structure, indent=2))

