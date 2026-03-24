
import subprocess
import sys

# Approach: Run slither with --config-disable-color and redirect to analyze
# Since slither crashes during IR generation on via-ir=true code,
# we need to catch that. But slither doesn't support partial analysis.
# 
# Alternative: Run slither directly on individual source files
# This avoids the monolithic compilation issue

# Let's try running slither on individual source files that don't have via_ir issues
# First, let's list all the project source files
import glob

src_files = glob.glob("/home/dok/web3_2/doppler_02/src/**/*.sol", recursive=True)
print(f"Found {len(src_files)} source files")
for f in sorted(src_files):
    print(f"  {f}")

