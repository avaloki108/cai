
import os
import json

# Read build-info and create dummy foundry-pp files
build_info_path = "/home/dok/web3_2/doppler_02/out/build-info/586cd7dd49189d7a.json"
project_dir = "/home/dok/web3_2/doppler_02"

with open(build_info_path, "r") as f:
    data = json.load(f)

# Create dummy foundry-pp files
foundry_pp_dir = os.path.join(project_dir, "foundry-pp")
os.makedirs(foundry_pp_dir, exist_ok=True)

foundry_pp_refs = set()
for key in data.get("input", {}).get("sources", {}).items():
    if "foundry-pp" in key:
        foundry_pp_refs.add(key)

created_count = 0
for ref in foundry_pp_refs:
    filepath = os.path.join(project_dir, ref)
    if not os.path.exists(filepath):
        # Get the source content from build-info or create a minimal placeholder
        source_content = data["input"]["sources"].get(ref, {}).get("content", "// placeholder")
        if source_content:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(source_content)
            created_count += 1

print(f"Created {created_count} dummy foundry-pp files in {foundry_pp_dir}")

