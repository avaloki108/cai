# Web3 Security Tools for CAI Bug Bounty Agent

This package integrates professional web3 security tools into the CAI bug bounty hunting framework, enabling comprehensive smart contract analysis, fuzzing, and vulnerability detection.

## Available Tools

### 1. Slither - Static Analysis
**Location:** `/home/dok/tools/slither/`

Slither is a static analysis framework for Solidity that detects vulnerabilities and code quality issues.

**Functions:**
- `slither_analyze(target, args)` - Run comprehensive static analysis
- `slither_check_upgradeability(target, proxy_address, args)` - Check upgradeability issues

**Example Usage:**
```python
# Basic analysis
result = slither_analyze("/path/to/contract.sol")

# Detect specific vulnerability
result = slither_analyze("/path/to/contract.sol", "--detect reentrancy")

# Generate human-readable summary
result = slither_analyze("/path/to/project", "--print human-summary")

# Check proxy upgradeability
result = slither_check_upgradeability("/path/to/implementation.sol", "0x...")
```

### 2. Mythril - Symbolic Execution
**Location:** `/home/dok/tools/mythril2.0/`

Mythril performs symbolic execution and SMT solving to detect complex vulnerabilities.

**Functions:**
- `mythril_analyze(target, args)` - Run symbolic execution analysis
- `mythril_disassemble(target, args)` - Disassemble EVM bytecode
- `mythril_read_storage(address, position, rpc_url, args)` - Read contract storage

**Example Usage:**
```python
# Analyze Solidity file
result = mythril_analyze("contract.sol")

# Analyze on-chain contract
result = mythril_analyze("0x...", "-a 0x... --rpc https://mainnet.infura.io/...")

# JSON output with timeout
result = mythril_analyze("contract.sol", "-o json --execution-timeout 300")

# Disassemble bytecode
result = mythril_disassemble("bytecode.bin")
```

### 3. Securify - Formal Verification
**Location:** `/home/dok/tools/securify2.5/`

Securify uses datalog-based static analysis and formal verification techniques.

**Functions:**
- `securify_analyze(target, args)` - Run formal verification
- `securify_compliance_check(target, standard, args)` - Check compliance with standards

**Example Usage:**
```python
# Basic analysis
result = securify_analyze("contract.sol")

# With timeout and JSON output
result = securify_analyze("contract.sol", "--timeout 300 --output-format json")

# Check ERC20 compliance
result = securify_compliance_check("token.sol", "erc20")
```

### 4. Echidna - Property-Based Fuzzing
**Location:** `/home/dok/tools/echidna/`

Echidna is a fast smart contract fuzzer using property-based testing.

**Functions:**
- `echidna_fuzz(target, contract, args)` - Run property-based fuzzing
- `echidna_assertion_mode(target, contract, args)` - Test assertions
- `echidna_coverage(target, contract, args)` - Generate coverage reports

**Example Usage:**
```python
# Basic fuzzing
result = echidna_fuzz("contract.sol")

# Specific contract with config
result = echidna_fuzz("contracts/", "MyToken", "--config echidna.yaml")

# Extended fuzzing campaign
result = echidna_fuzz("contract.sol", "", "--test-limit 100000 --seq-len 150")

# Assertion testing
result = echidna_assertion_mode("contract.sol", "MyContract")

# Coverage analysis
result = echidna_coverage("contract.sol", "", "--coverage-formats html")
```

### 5. Medusa - Coverage-Guided Fuzzing
**Location:** `/home/dok/tools/medusa/`

Medusa is a parallelized, coverage-guided fuzzer for Solidity smart contracts.

**Functions:**
- `medusa_fuzz(target, args)` - Run coverage-guided fuzzing
- `medusa_init(project_dir, args)` - Initialize Medusa configuration
- `medusa_test(target, test_name, args)` - Run specific tests

**Example Usage:**
```python
# Basic fuzzing
result = medusa_fuzz("./project")

# With custom config
result = medusa_fuzz("./project", "--config custom-medusa.json")

# Parallel fuzzing with limits
result = medusa_fuzz("./project", "--test-limit 10000 --timeout 300 --workers 20")

# Initialize new project
result = medusa_init("./new-project")

# Run specific test
result = medusa_test("./project", "test_invariant")
```

### 6. Fuzz-Utils - Fuzzing Utilities
**Location:** `/home/dok/tools/fuzz-utils/`

Collection of utilities for fuzzing campaigns, corpus management, and coverage analysis.

**Functions:**
- `fuzz_utils_run(tool, args)` - Run specific fuzz utility
- `generate_fuzz_seeds(target, output_dir, args)` - Generate seed corpus
- `minimize_fuzz_corpus(input_dir, output_dir, args)` - Minimize corpus
- `analyze_fuzz_coverage(coverage_data, args)` - Analyze coverage data

**Example Usage:**
```python
# Generate seeds
result = generate_fuzz_seeds("contract.sol", "./seeds")

# Minimize corpus
result = minimize_fuzz_corpus("./corpus", "./min-corpus")

# Analyze coverage
result = analyze_fuzz_coverage("./coverage-data")

# Run custom utility
result = fuzz_utils_run("mutator", "--input test.json --output mutated/")
```

## Integration with Bug Bounty Agent

All tools are automatically available to the Bug Bounty Agent in CAI. The agent can:

1. **Static Analysis**: Use Slither, Mythril, and Securify to detect known vulnerabilities
2. **Dynamic Testing**: Deploy Echidna and Medusa for fuzzing campaigns
3. **Corpus Management**: Use fuzz-utils to optimize fuzzing efficiency
4. **Multi-Tool Workflow**: Combine tools for comprehensive security assessment

## Typical Workflow

```python
# 1. Initial reconnaissance with Slither
slither_results = slither_analyze("target-contract.sol", "--print human-summary")

# 2. Deep analysis with Mythril
mythril_results = mythril_analyze("target-contract.sol", "-o json")

# 3. Compliance checking
compliance = securify_compliance_check("target-contract.sol", "erc20")

# 4. Fuzzing campaign with Echidna
echidna_results = echidna_fuzz("target-contract.sol", "", "--test-limit 50000")

# 5. Parallel fuzzing with Medusa
medusa_results = medusa_fuzz("./project", "--workers 20 --timeout 600")

# 6. Coverage analysis
coverage = echidna_coverage("target-contract.sol")
```

## Tool Paths Configuration

All tools are expected to be installed at:
- Slither: `/home/dok/tools/slither/`
- Mythril: `/home/dok/tools/mythril2.0/`
- Securify: `/home/dok/tools/securify2.5/`
- Echidna: `/home/dok/tools/echidna/`
- Medusa: `/home/dok/tools/medusa/`
- Fuzz-utils: `/home/dok/tools/fuzz-utils/`

If your tools are installed in different locations, update the paths in the respective tool files.

## Notes

- **Timeouts**: Fuzzing tools (Echidna, Medusa) have extended default timeouts (600-900 seconds)
- **Parallel Execution**: Medusa supports parallel workers for faster fuzzing
- **Output Formats**: Most tools support JSON output for programmatic parsing
- **Configuration Files**: Echidna and Medusa support YAML/JSON config files for advanced settings

## Bug Bounty Agent Enhancement

The bug bounty agent (`bug_bounter.py`) now includes all these tools by default, enabling:

- Automated smart contract vulnerability scanning
- Multi-tool correlation for high-confidence findings
- Fuzzing campaigns for edge case discovery
- Formal verification for critical contracts
- Coverage-guided testing for thorough analysis

## Further Reading

- [Slither Documentation](https://github.com/crytic/slither)
- [Mythril Documentation](https://github.com/ConsenSys/mythril)
- [Securify Documentation](https://github.com/eth-sri/securify2)
- [Echidna Documentation](https://github.com/crytic/echidna)
- [Medusa Documentation](https://github.com/crytic/medusa)
