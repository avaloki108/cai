
import subprocess, os

# We need to compile the project WITHOUT via_ir for slither to work
# Slither can't handle via_ir=true due to an IR generation bug
# Strategy: 
# 1. Create a temp foundry config with via_ir=false
# 2. Compile with forge build --force
# 3. Run slither with --foundry-ignore-compile

os.chdir("/home/dok/web3_2/doppler_02")

# Read the current foundry.toml
with open("foundry.toml", "r") as f:
    content = f.read()

# Create a slither-specific config with via_ir = false
slither_config = content.replace("via_ir = true", "via_ir = false")

# Write to a temp config file
with open("foundry.slither.toml", "w") as f:
    f.write(slither_config)

print("Created foundry.slither.toml with via_ir = false")
print("Original via_ir setting:", "via_ir = true" in content)
print("Modified via_ir setting:", "via_ir = true" in slither_config)

