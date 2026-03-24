
import json

build_info_path = "/home/dok/web3_2/doppler_02/out/build-info/586cd7dd49189d7a.json"
with open(build_info_path, "r") as f:
    data = json.load(f)

# Check one foundry-pp entry
key = "foundry-pp/DeployHelper137.sol"
entry = data["input"]["sources"].get(key, {})
print(f"Key: {key}")
print(f"Keys in entry: {list(entry.keys())}")
print(f"Content length: {len(entry.get('content', ''))}")
print(f"Content preview: {entry.get('content', '')[:200]}")

