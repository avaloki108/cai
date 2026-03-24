
import os
import json

# Check the build-info to find what foundry-pp files are referenced
build_info_dir = "/home/dok/web3_2/doppler_02/out/build-info"
build_info_files = os.listdir(build_info_dir)
print(f"Build info files: {build_info_files}")

# Read the build-info JSON to find the foundry-pp references
with open(os.path.join(build_info_dir, build_info_files[0]), "r") as f:
    data = json.load(f)

# Find all foundry-pp references
foundry_pp_refs = set()
for key, value in data.get("input", {}).get("sources", {}).items():
    if "foundry-pp" in key:
        foundry_pp_refs.add(key)

print(f"\nFound {len(foundry_pp_refs)} foundry-pp references:")
for ref in sorted(foundry_pp_refs)[:20]:
    print(f"  {ref}")
if len(foundry_pp_refs) > 20:
    print(f"  ... and {len(foundry_pp_refs) - 20} more")

