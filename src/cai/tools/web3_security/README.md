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

### 7. Gambit - Symbolic Execution
**Location:** `/home/dok/tools/W3-AUDIT/gambit/`

Gambit performs symbolic execution to explore contract behavior and find complex vulnerabilities.

**Functions:**
- `gambit_analyze(target, args)` - Run symbolic execution analysis
- `gambit_verify_property(target, property_file, args)` - Verify specific properties
- `gambit_explore_paths(target, max_paths, args)` - Explore execution paths

**Example Usage:**
```python
# Basic analysis
result = gambit_analyze("contract.sol")

# Verify property
result = gambit_verify_property("contract.sol", "property.spec")

# Explore paths
result = gambit_explore_paths("contract.sol", 200)
```

### 8. Clorgetizer - Gas Analysis
**Location:** `/home/dok/tools/W3-AUDIT/clorgetizer/`

Clorgetizer analyzes gas usage, identifies expensive operations, and suggests optimizations.

**Functions:**
- `clorgetizer_analyze(target, args)` - Run gas analysis
- `clorgetizer_compare_versions(old_version, new_version, args)` - Compare gas usage
- `clorgetizer_optimize(target, args)` - Generate optimization suggestions

**Example Usage:**
```python
# Gas analysis
result = clorgetizer_analyze("contract.sol")

# Compare versions
result = clorgetizer_compare_versions("v1.sol", "v2.sol")

# Get optimizations
result = clorgetizer_optimize("contract.sol")
```

### 9. Certora Prover - Formal Verification
**Location:** `/home/dok/tools/W3-AUDIT/certora-prover/`

Certora Prover uses formal methods to mathematically prove contract properties.

**Functions:**
- `certora_verify(target, spec_file, args)` - Run formal verification
- `certora_run_tests(target, test_file, args)` - Run test scenarios
- `certora_check_invariants(target, invariant_file, args)` - Check invariants

**Example Usage:**
```python
# Formal verification
result = certora_verify("contract.sol", "spec.spec")

# Run tests
result = certora_run_tests("contract.sol", "tests.spec")

# Check invariants
result = certora_check_invariants("contract.sol", "invariants.spec")
```

### 10. Oyente Plus - Symbolic Execution
**Location:** `/home/dok/tools/W3-AUDIT/oyente-plus/`

Oyente Plus performs symbolic execution to detect vulnerabilities like reentrancy and overflow.

**Functions:**
- `oyente_analyze(target, args)` - Run symbolic execution analysis
- `oyente_check_vulnerability(target, vuln_type, args)` - Check specific vulnerabilities
- `oyente_compare_contracts(contract1, contract2, args)` - Compare contracts

**Example Usage:**
```python
# Basic analysis
result = oyente_analyze("contract.sol")

# Check reentrancy
result = oyente_check_vulnerability("contract.sol", "reentrancy")

# Compare contracts
result = oyente_compare_contracts("old.sol", "new.sol")
```

### 11. Auditor Framework - Comprehensive Auditing
**Location:** `/home/dok/tools/auditor-framework/`

Comprehensive auditing framework providing unified analysis across multiple techniques.

**Functions:**
- `auditor_run_audit(target, audit_type, args)` - Run comprehensive audit
- `auditor_check_compliance(target, standard, args)` - Check compliance
- `auditor_generate_report(audit_data, format_type, args)` - Generate reports
- `auditor_scan_dependencies(target, args)` - Scan dependencies

**Example Usage:**
```python
# Full audit
result = auditor_run_audit("contract.sol", "full")

# Check ERC20 compliance
result = auditor_check_compliance("token.sol", "erc20")

# Generate report
result = auditor_generate_report("./audit-data", "html")

# Scan dependencies
result = auditor_scan_dependencies("contract.sol")
```

## Integration with Bug Bounty Agent

All tools are automatically available to the Bug Bounty Agent in CAI. The agent can:

1. **Static Analysis**: Use Slither, Mythril, Securify, and Oyente Plus to detect known vulnerabilities
2. **Formal Verification**: Apply Certora Prover for mathematical proof of contract properties
3. **Symbolic Execution**: Leverage Gambit and Oyente Plus for deep behavioral analysis
4. **Gas Optimization**: Use Clorgetizer to identify expensive operations and optimization opportunities
5. **Dynamic Testing**: Deploy Echidna and Medusa for comprehensive fuzzing campaigns
6. **Corpus Management**: Use fuzz-utils to optimize fuzzing efficiency
7. **Comprehensive Auditing**: Run full audits with the Auditor Framework
8. **Multi-Tool Workflow**: Combine all tools for thorough, multi-layered security assessment

## Typical Workflow

```python
# 1. Initial reconnaissance with Slither
slither_results = slither_analyze("target-contract.sol", "--print human-summary")

# 2. Deep analysis with Mythril
mythril_results = mythril_analyze("target-contract.sol", "-o json")

# 3. Symbolic execution with Oyente Plus
oyente_results = oyente_analyze("target-contract.sol", "--json")

# 4. Formal verification with Certora
certora_results = certora_verify("target-contract.sol", "security.spec")

# 5. Gas analysis with Clorgetizer
gas_analysis = clorgetizer_analyze("target-contract.sol")

# 6. Fuzzing campaign with Echidna
echidna_results = echidna_fuzz("target-contract.sol", "", "--test-limit 50000")

# 7. Parallel fuzzing with Medusa
medusa_results = medusa_fuzz("./project", "--workers 20 --timeout 600")

# 8. Symbolic execution with Gambit
gambit_results = gambit_analyze("target-contract.sol", "--timeout 300")

# 9. Comprehensive audit with Auditor Framework
audit_report = auditor_run_audit("target-contract.sol", "full", "--format json")

# 10. Coverage analysis
coverage = echidna_coverage("target-contract.sol")
```

## Memory + RAG

Use the built-in memory bank and knowledge base to reuse prior insights and best practices:

```python
# Query best practices and attack vectors
kb_hits = web3_kb_query("oracle manipulation and flash loans", top_k=5)

# Query prior audit memory
mem_hits = web3_memory_query("lending protocol liquidation edge cases", top_k=5)

# Unified RAG across knowledge base and memory
rag_hits = web3_rag_query("bridge replay protection", top_k=5)
```

## Tool Paths Configuration

All tools are expected to be installed at:
- Slither: `/home/dok/tools/W3-AUDIT/slither/`
- Mythril: `/home/dok/tools/mythril2.0/`
- Securify: `/home/dok/tools/securify2.5/`
- Echidna: `/home/dok/tools/echidna/`
- Medusa: `/home/dok/tools/medusa/`
- Fuzz-utils: `/home/dok/tools/fuzz-utils/`
- Gambit: `/home/dok/tools/W3-AUDIT/gambit/`
- Clorgetizer: `/home/dok/tools/W3-AUDIT/clorgetizer/`
- Certora Prover: `/home/dok/tools/W3-AUDIT/certora-prover/`
- Oyente Plus: `/home/dok/tools/W3-AUDIT/oyente-plus/`
- Auditor Framework: `/home/dok/tools/auditor-framework/`

If your tools are installed in different locations, update the paths in the respective tool files or set environment variables.

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
- [Gambit Documentation](https://github.com/crytic/gambit)
- [Clorgetizer Documentation](https://github.com/crytic/clorgetizer)
- [Certora Prover Documentation](https://docs.certora.com/)
- [Oyente Documentation](https://github.com/enzymefinance/oyente)
