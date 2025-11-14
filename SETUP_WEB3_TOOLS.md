# Web3 Security Tools Setup Guide

This guide helps you set up the web3 security tools for use with the CAI bug bounty agent.

## Tools Overview

The following tools have been integrated:
- ✅ **Slither** - Static analysis (Ready)
- ✅ **Mythril** - Symbolic execution (Ready)
- ✅ **Securify** - Formal verification (Ready)
- ⚠️  **Echidna** - Property-based fuzzing (Needs compilation)
- ⚠️  **Medusa** - Coverage-guided fuzzing (Needs compilation)
- ✅ **Fuzz-utils** - Fuzzing utilities (Ready)

## Quick Status Check

Run this command to check tool availability:

```bash
cd /home/dok/tools/cai
python test_web3_integration.py
```

## Tool Setup Instructions

### 1. Slither (Already Installed)
Location: `/home/dok/tools/slither/`

**Verify:**
```bash
/home/dok/tools/slither/slither --version
```

### 2. Mythril (Already Installed)
Location: `/home/dok/tools/mythril2.0/`

**Verify:**
```bash
/home/dok/tools/mythril2.0/myth version
```

### 3. Securify (Already Installed)
Location: `/home/dok/tools/securify2.5/`

**Verify:**
```bash
/home/dok/tools/securify2.5/securify --help
```

### 4. Echidna (Needs Setup)

Echidna is a Haskell-based fuzzer. You need to either:

**Option A: Install pre-built binary**
```bash
cd /home/dok/tools/echidna
# Download latest release from https://github.com/crytic/echidna/releases
wget https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Linux.tar.gz
tar xzf echidna-2.2.1-Linux.tar.gz
# Binary will be at echidna
```

**Option B: Build from source (requires Stack/Haskell)**
```bash
cd /home/dok/tools/echidna
stack install
# Or use nix: nix-build
```

**Option C: Use via PATH**
```bash
# If you have echidna installed system-wide
which echidna
# Set environment variable:
export WEB3_ECHIDNA_PATH=$(which echidna)
```

### 5. Medusa (Needs Setup)

Medusa is a Go-based fuzzer. Build from source:

**Option A: Build from source (requires Go 1.20+)**
```bash
cd /home/dok/tools/medusa
go build -o medusa cmd/medusa/main.go
# Or
make build
```

**Option B: Use pre-built binary**
```bash
cd /home/dok/tools/medusa
# Download from releases
wget https://github.com/crytic/medusa/releases/download/v0.1.0/medusa-linux-x64
chmod +x medusa-linux-x64
mv medusa-linux-x64 medusa
```

**Option C: Use via PATH**
```bash
# If installed system-wide
which medusa
export WEB3_MEDUSA_PATH=$(which medusa)
```

### 6. Fuzz-utils (Already Available)
Location: `/home/dok/tools/fuzz-utils/`

## Environment Variables Configuration

You can override default tool paths using environment variables:

```bash
# Add to your ~/.bashrc or ~/.zshrc
export WEB3_SLITHER_PATH="/custom/path/to/slither"
export WEB3_MYTHRIL_PATH="/custom/path/to/myth"
export WEB3_SECURIFY_PATH="/custom/path/to/securify"
export WEB3_ECHIDNA_PATH="/custom/path/to/echidna"
export WEB3_MEDUSA_PATH="/custom/path/to/medusa"
export WEB3_FUZZ_UTILS_PATH="/custom/path/to/fuzz-utils"
```

## Using Tools with CAI

Once tools are set up, you can use them with the bug bounty agent:

```bash
# Start CAI with bug bounty agent
python -m cai --agent bug_bounter

# Example queries:
# "Analyze this smart contract with Slither: /path/to/contract.sol"
# "Run Mythril on contract at 0x... using RPC https://mainnet.infura.io/..."
# "Fuzz this contract with Echidna for 10000 test cases"
# "Run Medusa fuzzing with 20 workers on ./project"
```

## Tool-Specific Configuration Files

### Echidna Configuration (echidna.yaml)
```yaml
testLimit: 50000
seqLen: 100
shrinkLimit: 5000
timeout: 0
workers: 1
corpusDir: "corpus"
coverage: true
```

### Medusa Configuration (medusa.json)
```json
{
  "fuzzing": {
    "workers": 10,
    "testLimit": 0,
    "timeout": 0,
    "corpusDirectory": "corpus"
  },
  "compilation": {
    "platform": "crytic-compile"
  }
}
```

## Testing the Integration

### Test Individual Tools:

```bash
# Test Slither
python -c "from cai.tools.web3_security import slither_analyze; print(slither_analyze.__doc__)"

# Test Mythril
python -c "from cai.tools.web3_security import mythril_analyze; print(mythril_analyze.__doc__)"

# Test all imports
python test_web3_integration.py
```

### Run Sample Analysis:

Create a simple test contract:

```solidity
// test.sol
pragma solidity ^0.8.0;

contract Test {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }
}
```

Test with tools:
```bash
# Using Python
python -c "
from cai.tools.web3_security import slither_analyze
result = slither_analyze('test.sol')
print(result)
"
```

## Troubleshooting

### Tool not found error
- Check if the tool is executable: `ls -la /home/dok/tools/*/`
- Verify paths in [config.py](src/cai/tools/web3_security/config.py)
- Set environment variable to override: `export WEB3_TOOLNAME_PATH=/path/to/tool`

### Permission denied
```bash
chmod +x /home/dok/tools/slither/slither
chmod +x /home/dok/tools/mythril2.0/myth
# etc.
```

### Import errors
Make sure you're in the CAI environment:
```bash
cd /home/dok/tools/cai
# Activate virtual environment if using one
source venv/bin/activate
# Or ensure PYTHONPATH includes src/
export PYTHONPATH=/home/dok/tools/cai/src:$PYTHONPATH
```

## Advanced Configuration

### Using Tools via Docker

If you prefer Docker containers:

```bash
# Example for Mythril
docker pull mythril/myth
# Update tool wrapper to use docker command
export WEB3_MYTHRIL_PATH="docker run --rm -v $(pwd):/tmp mythril/myth"
```

### Custom Tool Wrappers

You can create custom wrappers in `src/cai/tools/web3_security/` following the pattern:

```python
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import get_tool_path

@function_tool
def my_tool(target: str, args: str = "", ctf=None) -> str:
    """Tool documentation"""
    tool_path = get_tool_path('my_tool')
    command = f'{tool_path} {args} {target}'
    return run_command(command, ctf=ctf)
```

## Additional Resources

- [Slither Documentation](https://github.com/crytic/slither)
- [Mythril Documentation](https://mythril-classic.readthedocs.io/)
- [Securify Documentation](https://github.com/eth-sri/securify2)
- [Echidna Tutorial](https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/echidna)
- [Medusa Documentation](https://github.com/crytic/medusa)

## Support

If you encounter issues:
1. Check tool paths: `python -c "from cai.tools.web3_security.config import get_all_tool_paths; print(get_all_tool_paths())"`
2. Verify tool availability: `python -c "from cai.tools.web3_security.config import get_available_tools; print(get_available_tools())"`
3. Review error logs in CAI output
4. Check individual tool documentation for specific issues

## Summary

✅ **Ready to use**: Slither, Mythril, Securify, Fuzz-utils
⚠️  **Needs setup**: Echidna, Medusa (compile or download binaries)

After setup, all tools will be available to the CAI bug bounty agent for comprehensive smart contract security analysis!
