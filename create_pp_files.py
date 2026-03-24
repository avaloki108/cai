
import os
import json

build_info_path = "/home/dok/web3_2/doppler_02/out/build-info/586cd7dd49189d7a.json"
project_dir = "/home/dok/web3_2/doppler_02"

with open(build_info_path, "r") as f:
    data = json.load(f)

sources = data.get("input", {}).get("sources", {})

foundry_pp_dir = os.path.join(project_dir, "foundry-pp")
os.makedirs(foundry_pp_dir, exist_ok=True)

created_count = 0
for key, value in sources.items():
    if "foundry-pp" in key:
        filepath = os.path.join(project_dir, key)
        content = value.get("content", "")
        if content and not os.path.exists(filepath):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)
            created_count += 1
            print(f"  Created: {key} ({len(content)} chars)")
        elif os.path.exists(filepath):
            print(f"  Already exists: {key}")
        else:
            print(f"  No content: {key}")

print(f"\nCreated {created_count} files total")

