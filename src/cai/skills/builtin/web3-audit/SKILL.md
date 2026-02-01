---
name: web3-audit
description: Web3 smart contract security audit methodology and patterns. Use when auditing Solidity/Vyper contracts for vulnerabilities.
tags: web3, security, audit, solidity, defi
alwaysApply: false
---

# Web3 Smart Contract Audit Skill

## Audit Methodology

### Phase 1: Reconnaissance
1. Map all contracts and their relationships
2. Identify external dependencies (oracles, DEXs, bridges)
3. Review prior audits and known issues
4. Understand the protocol's value flows

### Phase 2: Static Analysis
Run automated tools first:
```bash
slither .                    # General vulnerability detection
mythril analyze <contract>   # Symbolic execution
```

### Phase 3: Manual Review Focus Areas

#### Access Control
- Check all privileged functions have proper modifiers
- Verify role-based access is correctly implemented
- Look for missing access controls on critical functions

#### Reentrancy
- External calls before state updates
- Missing nonReentrant modifiers
- Cross-function and cross-contract reentrancy

#### Economic Logic
- Rounding errors in fee calculations
- Flash loan attack vectors
- Oracle manipulation opportunities
- Slippage protection

#### State Management
- Initialization vulnerabilities
- Upgrade safety (storage layout)
- Pause functionality gaps

### Phase 4: Proof of Concept
For each finding, create a minimal PoC:
```solidity
function testExploit() public {
    // Setup
    // Attack
    // Assert impact
}
```

## Common Vulnerability Patterns

### Reentrancy
```solidity
// VULNERABLE
function withdraw() external {
    uint bal = balances[msg.sender];
    (bool success,) = msg.sender.call{value: bal}("");
    balances[msg.sender] = 0;  // State update AFTER call
}
```

### Missing Access Control
```solidity
// VULNERABLE
function setPrice(uint _price) external {
    price = _price;  // Missing onlyOwner
}
```

### Unchecked Return Values
```solidity
// VULNERABLE
token.transfer(recipient, amount);  // Return not checked
```

## Report Format
```markdown
## [SEVERITY] Title

### Summary
One-line description

### Vulnerability Detail
Technical explanation with code references

### Impact
What can an attacker do?

### Code Snippet
```solidity
// Vulnerable code here
```

### Recommendation
How to fix it
```
