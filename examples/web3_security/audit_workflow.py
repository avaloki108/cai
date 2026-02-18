"""
Web3 Security Audit Workflow Example

Demonstrates how to use the Aegis agent ensemble for comprehensive
smart contract security auditing.

This example shows:
1. Running multiple specialized analyzers in parallel
2. Coordinating adversarial review with Skeptic agents
3. Calculating MEV exposure
4. Generating comprehensive audit reports

Usage:
    python examples/web3_security/audit_workflow.py --target ./contracts/
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, List, Any

# CAI imports
from cai.agents import get_agent_by_name
from cai.sdk.agents import Runner


# Sample vulnerable contract for demonstration
SAMPLE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @dev Example contract with multiple security issues for demonstration
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy
    // State update happens AFTER external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update - REENTRANCY VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
    
    // VULNERABILITY 2: Missing access control
    // Anyone can change owner
    function setOwner(address newOwner) external {
        owner = newOwner;  // No onlyOwner modifier!
    }
    
    // VULNERABILITY 3: No slippage protection
    // Swap function vulnerable to sandwich attacks
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        // No amountOutMin parameter - SANDWICH VULNERABLE
        // No deadline parameter - can be delayed
        amountOut = _getAmountOut(tokenIn, tokenOut, amountIn);
        // ... swap logic
    }
    
    // VULNERABILITY 4: Oracle manipulation
    // Uses spot price without TWAP
    function liquidate(address borrower) external {
        uint256 price = _getSpotPrice();  // Can be manipulated
        // ... liquidation logic
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    
    function _getAmountOut(address, address, uint256 amountIn) 
        internal pure returns (uint256) {
        return amountIn * 99 / 100;  // Simplified
    }
    
    function _getSpotPrice() internal pure returns (uint256) {
        return 1000;  // Simplified
    }
}
'''


def run_skeptic_alpha_analysis(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Run Skeptic Alpha logical assumption analysis."""
    from cai.agents.skeptic_alpha import challenge_assumptions
    
    result = challenge_assumptions(
        finding_description=finding.get("description", ""),
        stated_assumptions=finding.get("assumptions", "")
    )
    return json.loads(result)


def run_skeptic_beta_analysis(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Run Skeptic Beta economic viability analysis."""
    from cai.agents.skeptic_beta import calculate_attack_cost, analyze_roi
    
    # Calculate attack cost
    cost_result = calculate_attack_cost(
        attack_description=finding.get("description", ""),
        gas_estimate=finding.get("gas_estimate", 300000),
        gas_price_gwei=50.0,
        flash_loan_needed=finding.get("requires_flash_loan", False),
        flash_loan_amount=finding.get("flash_loan_amount", 0)
    )
    cost = json.loads(cost_result)
    
    # Analyze ROI
    roi_result = analyze_roi(
        attack_cost_eth=cost.get("total_cost_eth", 0),
        attack_profit_eth=finding.get("potential_profit", 1.0),
        success_probability=finding.get("success_probability", 0.8)
    )
    roi = json.loads(roi_result)
    
    return {
        "cost_analysis": cost,
        "roi_analysis": roi,
        "economically_viable": roi.get("economically_viable", False)
    }


def run_skeptic_gamma_analysis(finding: Dict[str, Any], contract_code: str) -> Dict[str, Any]:
    """Run Skeptic Gamma defense mechanism analysis."""
    from cai.agents.skeptic_gamma import (
        find_access_controls,
        find_reentrancy_guards,
        find_input_validation
    )
    
    results = {}
    
    # Check for access controls if relevant
    if "access" in finding.get("type", "").lower():
        access_result = find_access_controls(
            function_name=finding.get("function", ""),
            contract_code=contract_code
        )
        results["access_controls"] = json.loads(access_result)
    
    # Check for reentrancy guards if relevant
    if "reentrancy" in finding.get("type", "").lower():
        guard_result = find_reentrancy_guards(
            function_name=finding.get("function", ""),
            contract_code=contract_code
        )
        results["reentrancy_guards"] = json.loads(guard_result)
    
    # Check input validation
    validation_result = find_input_validation(
        function_name=finding.get("function", ""),
        contract_code=contract_code
    )
    results["input_validation"] = json.loads(validation_result)
    
    return results


def run_mev_analysis(contract_code: str) -> Dict[str, Any]:
    """Run MEV vulnerability analysis."""
    from cai.agents.mev_analyzer import (
        analyze_sandwich_vulnerability,
        analyze_frontrun_vulnerability,
        calculate_mev_exposure
    )
    
    # Sandwich analysis
    sandwich_result = analyze_sandwich_vulnerability(contract_code)
    sandwich = json.loads(sandwich_result)
    
    # Frontrun analysis
    frontrun_result = analyze_frontrun_vulnerability(contract_code)
    frontrun = json.loads(frontrun_result)
    
    # Calculate typical MEV exposure
    mev_result = calculate_mev_exposure(
        function_type="swap",
        trade_size_eth=10.0,
        pool_liquidity_eth=1000.0,
        gas_price_gwei=50.0
    )
    mev = json.loads(mev_result)
    
    return {
        "sandwich_analysis": sandwich,
        "frontrun_analysis": frontrun,
        "mev_exposure": mev,
        "overall_mev_risk": "HIGH" if sandwich.get("verdict") == "VULNERABLE" else "LOW"
    }


def run_bridge_analysis(contract_code: str) -> Dict[str, Any]:
    """Run bridge security analysis (if contract is a bridge)."""
    from cai.agents.bridge_analyzer import (
        analyze_replay_protection,
        analyze_signature_verification,
        check_known_bridge_exploits
    )
    
    # Check if this looks like a bridge contract
    bridge_indicators = ["bridge", "relay", "message", "crosschain", "chainid"]
    is_bridge = any(ind in contract_code.lower() for ind in bridge_indicators)
    
    if not is_bridge:
        return {"is_bridge": False, "analysis": "Not a bridge contract"}
    
    replay_result = analyze_replay_protection(contract_code)
    sig_result = analyze_signature_verification(contract_code)
    exploit_result = check_known_bridge_exploits(contract_code)
    
    return {
        "is_bridge": True,
        "replay_protection": json.loads(replay_result),
        "signature_verification": json.loads(sig_result),
        "known_exploits": json.loads(exploit_result)
    }


def adversarial_review(findings: List[Dict], contract_code: str) -> List[Dict]:
    """
    Run findings through adversarial review pipeline.
    
    Pipeline: Skeptic Alpha -> Skeptic Beta -> Skeptic Gamma
    
    Findings must pass ALL skeptics to be validated.
    """
    validated_findings = []
    
    for finding in findings:
        print(f"\n[Adversarial Review] Analyzing: {finding.get('id', 'unknown')}")
        
        # Skeptic Alpha: Logical analysis
        alpha_result = run_skeptic_alpha_analysis(finding)
        alpha_pass = alpha_result.get("flaws_found", 0) == 0
        print(f"  - Skeptic Alpha: {'PASS' if alpha_pass else 'FAIL'}")
        
        # Skeptic Beta: Economic analysis
        beta_result = run_skeptic_beta_analysis(finding)
        beta_pass = beta_result.get("economically_viable", False)
        print(f"  - Skeptic Beta: {'PASS' if beta_pass else 'FAIL'}")
        
        # Skeptic Gamma: Defense analysis
        gamma_result = run_skeptic_gamma_analysis(finding, contract_code)
        # Pass if defenses are insufficient
        gamma_pass = any(
            r.get("verdict") in ["VULNERABLE", "UNPROTECTED", "UNVALIDATED"]
            for r in gamma_result.values()
            if isinstance(r, dict)
        )
        print(f"  - Skeptic Gamma: {'PASS' if gamma_pass else 'FAIL'}")
        
        # All skeptics must pass
        if alpha_pass and beta_pass and gamma_pass:
            finding["validated"] = True
            finding["skeptic_results"] = {
                "alpha": alpha_result,
                "beta": beta_result,
                "gamma": gamma_result
            }
            validated_findings.append(finding)
            print(f"  => VALIDATED")
        else:
            print(f"  => REJECTED")
    
    return validated_findings


def generate_audit_report(
    contract_name: str,
    validated_findings: List[Dict],
    mev_analysis: Dict,
    bridge_analysis: Dict
) -> str:
    """Generate comprehensive audit report."""
    
    report = f"""
================================================================================
                        WEB3 SECURITY AUDIT REPORT
================================================================================

Contract: {contract_name}
Generated by: CAI Aegis Agent Ensemble

================================================================================
                            EXECUTIVE SUMMARY
================================================================================

Total Findings: {len(validated_findings)}
Critical: {sum(1 for f in validated_findings if f.get('severity') == 'CRITICAL')}
High: {sum(1 for f in validated_findings if f.get('severity') == 'HIGH')}
Medium: {sum(1 for f in validated_findings if f.get('severity') == 'MEDIUM')}
Low: {sum(1 for f in validated_findings if f.get('severity') == 'LOW')}

MEV Risk: {mev_analysis.get('overall_mev_risk', 'N/A')}
Bridge Analysis: {'Applicable' if bridge_analysis.get('is_bridge') else 'Not Applicable'}

================================================================================
                            VALIDATED FINDINGS
================================================================================
"""
    
    for i, finding in enumerate(validated_findings, 1):
        report += f"""
[{i}] {finding.get('id', 'N/A')} - {finding.get('title', 'Untitled')}
    Severity: {finding.get('severity', 'N/A')}
    Type: {finding.get('type', 'N/A')}
    Function: {finding.get('function', 'N/A')}
    
    Description:
    {finding.get('description', 'No description')}
    
    Recommendation:
    {finding.get('recommendation', 'No recommendation')}
    
    Economic Analysis:
    - Attack Cost: {finding.get('skeptic_results', {}).get('beta', {}).get('cost_analysis', {}).get('total_cost_usd', 'N/A')} USD
    - Potential Profit: {finding.get('potential_profit', 'N/A')} ETH
    - ROI: {finding.get('skeptic_results', {}).get('beta', {}).get('roi_analysis', {}).get('roi_percentage', 'N/A')}%
    
    ---
"""
    
    report += f"""
================================================================================
                            MEV ANALYSIS
================================================================================

Sandwich Attack Risk: {mev_analysis.get('sandwich_analysis', {}).get('verdict', 'N/A')}
Frontrun Risk: {mev_analysis.get('frontrun_analysis', {}).get('verdict', 'N/A')}
Estimated MEV Exposure: {mev_analysis.get('mev_exposure', {}).get('potential_mev_usd', 'N/A')} USD

================================================================================
                            RECOMMENDATIONS
================================================================================

1. Fix all CRITICAL and HIGH severity findings before deployment
2. Implement slippage protection for swap functions
3. Add reentrancy guards to all external call patterns
4. Implement proper access control with timelocks
5. Consider using private transaction relays for MEV protection

================================================================================
                            DISCLAIMER
================================================================================

This report is generated by AI agents and should be reviewed by human auditors.
No automated tool can guarantee complete vulnerability coverage.

================================================================================
"""
    
    return report


def main():
    """Main audit workflow demonstration."""
    print("=" * 60)
    print("    CAI AEGIS WEB3 SECURITY AUDIT WORKFLOW")
    print("=" * 60)
    
    # Simulated findings (in real workflow, these come from static analysis)
    initial_findings = [
        {
            "id": "VUL-001",
            "title": "Reentrancy in withdraw()",
            "type": "reentrancy",
            "severity": "CRITICAL",
            "function": "withdraw",
            "description": "State update occurs after external call, allowing reentrancy attack",
            "assumptions": "Assumes attacker contract can reenter during callback",
            "gas_estimate": 500000,
            "requires_flash_loan": False,
            "potential_profit": 10.0,
            "success_probability": 0.9,
            "recommendation": "Move state update before external call or add nonReentrant modifier"
        },
        {
            "id": "VUL-002",
            "title": "Missing access control on setOwner()",
            "type": "access_control",
            "severity": "CRITICAL",
            "function": "setOwner",
            "description": "Anyone can change contract owner",
            "assumptions": "Assumes ownership can be transferred without authorization",
            "gas_estimate": 50000,
            "requires_flash_loan": False,
            "potential_profit": 100.0,  # Full control of contract
            "success_probability": 1.0,
            "recommendation": "Add onlyOwner modifier to setOwner function"
        },
        {
            "id": "VUL-003",
            "title": "Sandwich vulnerability in swap()",
            "type": "mev_sandwich",
            "severity": "HIGH",
            "function": "swap",
            "description": "Swap function lacks slippage protection",
            "assumptions": "Assumes swap transactions are visible in mempool",
            "gas_estimate": 300000,
            "requires_flash_loan": True,
            "flash_loan_amount": 100.0,
            "potential_profit": 0.5,
            "success_probability": 0.7,
            "recommendation": "Add amountOutMin and deadline parameters"
        }
    ]
    
    print(f"\n[1] Analyzing contract: VulnerableVault")
    print(f"    Initial findings: {len(initial_findings)}")
    
    # Run MEV analysis
    print("\n[2] Running MEV Analysis...")
    mev_results = run_mev_analysis(SAMPLE_CONTRACT)
    print(f"    MEV Risk: {mev_results['overall_mev_risk']}")
    
    # Run bridge analysis (will return not applicable for this contract)
    print("\n[3] Running Bridge Analysis...")
    bridge_results = run_bridge_analysis(SAMPLE_CONTRACT)
    print(f"    Is Bridge: {bridge_results['is_bridge']}")
    
    # Run adversarial review
    print("\n[4] Running Adversarial Review Pipeline...")
    validated = adversarial_review(initial_findings, SAMPLE_CONTRACT)
    print(f"\n    Validated findings: {len(validated)} / {len(initial_findings)}")
    
    # Generate report
    print("\n[5] Generating Audit Report...")
    report = generate_audit_report(
        "VulnerableVault",
        validated,
        mev_results,
        bridge_results
    )
    
    print(report)
    
    # Save report
    report_path = Path("audit_report.txt")
    report_path.write_text(report)
    print(f"\nReport saved to: {report_path.absolute()}")
    
    return validated, mev_results, bridge_results


if __name__ == "__main__":
    main()
