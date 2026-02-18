"""
Bridge/Cross-Chain Analyzer Agent

Specialized agent for analyzing cross-chain bridge security vulnerabilities.
Focuses on the most critical attack vectors in bridge protocols.

Key Attack Vectors:
- Message replay attacks across chains
- Chain ID validation bypasses
- Signature verification flaws
- Oracle/validator collusion
- Stuck message vulnerabilities
- Gas griefing on destination chains

Based on analysis of major bridge exploits:
- Ronin Bridge ($625M)
- Wormhole ($326M)
- Nomad ($190M)
- Harmony Horizon ($100M)
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ALIAS_API_KEY")
    or "sk-placeholder"
)


# Known bridge vulnerability patterns
BRIDGE_VULNERABILITY_PATTERNS = {
    "replay_attack": {
        "description": "Message can be replayed on same or different chain",
        "severity": "CRITICAL",
        "indicators": [
            r"!usedNonces\[",
            r"nonce\s*\+\+",
            r"messageHash",
            r"ecrecover",
        ],
        "mitigations": ["nonce tracking", "chain ID in hash", "message expiry"],
    },
    "chain_id_missing": {
        "description": "Chain ID not included in signed message",
        "severity": "CRITICAL",
        "indicators": [
            r"abi\.encodePacked\(",
            r"keccak256\(",
            r"sign\(",
        ],
        "mitigations": ["include chainId in hash", "EIP-712 typed data"],
    },
    "signature_malleability": {
        "description": "Signature can be modified without invalidating",
        "severity": "HIGH",
        "indicators": [
            r"ecrecover\(",
            r"recover\(",
            r"v\s*,\s*r\s*,\s*s",
        ],
        "mitigations": ["ECDSA library", "EIP-2098 compact signatures"],
    },
    "validator_threshold": {
        "description": "Insufficient validator/signer threshold",
        "severity": "HIGH",
        "indicators": [
            r"threshold",
            r"requiredSignatures",
            r"minSigners",
        ],
        "mitigations": ["2/3+ threshold", "time-delayed execution"],
    },
    "message_verification": {
        "description": "Insufficient message verification on destination",
        "severity": "CRITICAL",
        "indicators": [
            r"verifyProof",
            r"validateMessage",
            r"receiveMessage",
        ],
        "mitigations": ["merkle proof verification", "state root validation"],
    },
}


@function_tool
def analyze_replay_protection(
    contract_code: str,
    function_name: str = "",
    ctf=None
) -> str:
    """
    Analyze replay attack protection in bridge contract.
    
    Args:
        contract_code: Source code of the bridge contract
        function_name: Specific function to analyze (optional)
        
    Returns:
        Replay protection analysis
    """
    try:
        findings = []
        
        # Check for nonce usage
        has_nonce = bool(re.search(r'\bnonce\b', contract_code, re.IGNORECASE))
        has_nonce_tracking = bool(re.search(r'usedNonces\s*\[|processedNonces\s*\[|executedMessages\s*\[', contract_code))
        has_nonce_increment = bool(re.search(r'nonce\s*\+\+|nonce\s*\+=\s*1', contract_code))
        
        if not has_nonce:
            findings.append({
                "issue": "NO_NONCE_FOUND",
                "severity": "CRITICAL",
                "description": "No nonce mechanism detected - vulnerable to replay attacks",
                "recommendation": "Implement nonce tracking per message"
            })
        elif not has_nonce_tracking:
            findings.append({
                "issue": "NONCE_NOT_TRACKED",
                "severity": "HIGH",
                "description": "Nonce exists but may not be properly tracked for reuse prevention",
                "recommendation": "Use mapping to track used nonces"
            })
        
        # Check for message hash tracking
        has_message_hash = bool(re.search(r'messageHash|msgHash', contract_code))
        has_hash_tracking = bool(re.search(r'executed\s*\[|processed\s*\[', contract_code))
        
        if has_message_hash and not has_hash_tracking:
            findings.append({
                "issue": "HASH_NOT_TRACKED",
                "severity": "HIGH",
                "description": "Message hash computed but not tracked for replay prevention",
                "recommendation": "Store executed message hashes"
            })
        
        # Check for chain ID in message
        has_chain_id = bool(re.search(r'chainId|block\.chainid|getChainId', contract_code, re.IGNORECASE))
        
        if not has_chain_id:
            findings.append({
                "issue": "NO_CHAIN_ID",
                "severity": "CRITICAL",
                "description": "Chain ID not included in message - cross-chain replay possible",
                "recommendation": "Include source and destination chainId in signed message"
            })
        
        result = {
            "analysis_type": "replay_protection",
            "function": function_name or "contract-wide",
            "has_nonce": has_nonce,
            "has_nonce_tracking": has_nonce_tracking,
            "has_message_hash": has_message_hash,
            "has_chain_id": has_chain_id,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "PROTECTED" if len(findings) == 0 else "VULNERABLE",
            "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if findings else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing replay protection: {str(e)}"})


@function_tool
def analyze_signature_verification(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze signature verification security in bridge contract.
    
    Args:
        contract_code: Source code of the bridge contract
        
    Returns:
        Signature verification analysis
    """
    try:
        findings = []
        
        # Check for ecrecover usage
        uses_ecrecover = bool(re.search(r'\becrecover\s*\(', contract_code))
        uses_ecdsa_library = bool(re.search(r'ECDSA\.recover|ECDSA\.tryRecover', contract_code))
        
        if uses_ecrecover and not uses_ecdsa_library:
            findings.append({
                "issue": "RAW_ECRECOVER",
                "severity": "HIGH",
                "description": "Using raw ecrecover instead of ECDSA library - vulnerable to signature malleability",
                "recommendation": "Use OpenZeppelin ECDSA library for signature recovery"
            })
        
        # Check for zero address validation
        has_zero_check = bool(re.search(r'signer\s*!=\s*address\s*\(\s*0\s*\)|recovered\s*!=\s*address\s*\(\s*0\s*\)', contract_code))
        
        if uses_ecrecover and not has_zero_check:
            findings.append({
                "issue": "NO_ZERO_ADDRESS_CHECK",
                "severity": "HIGH",
                "description": "ecrecover can return address(0) for invalid signatures",
                "recommendation": "Check recovered address != address(0)"
            })
        
        # Check for multi-sig threshold
        has_threshold = bool(re.search(r'threshold|requiredSignatures|minSigners|validatorCount', contract_code, re.IGNORECASE))
        threshold_value = re.search(r'threshold\s*[=:]\s*(\d+)|requiredSignatures\s*[=:]\s*(\d+)', contract_code)
        
        if has_threshold:
            if threshold_value:
                val = int(threshold_value.group(1) or threshold_value.group(2))
                if val < 2:
                    findings.append({
                        "issue": "LOW_THRESHOLD",
                        "severity": "CRITICAL",
                        "description": f"Signature threshold is {val} - single point of failure",
                        "recommendation": "Require at least 2/3 of validators"
                    })
        else:
            findings.append({
                "issue": "NO_MULTI_SIG",
                "severity": "HIGH",
                "description": "No multi-signature requirement detected",
                "recommendation": "Implement multi-sig with adequate threshold"
            })
        
        # Check for signature uniqueness
        has_sig_tracking = bool(re.search(r'usedSignatures\[|executedSignatures\[', contract_code))
        
        result = {
            "analysis_type": "signature_verification",
            "uses_ecrecover": uses_ecrecover,
            "uses_ecdsa_library": uses_ecdsa_library,
            "has_zero_check": has_zero_check,
            "has_threshold": has_threshold,
            "has_sig_tracking": has_sig_tracking,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "SECURE" if len(findings) == 0 else "VULNERABLE",
            "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if findings else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing signature verification: {str(e)}"})


@function_tool
def analyze_message_validation(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze message validation on bridge destination.
    
    Args:
        contract_code: Source code of the bridge contract
        
    Returns:
        Message validation analysis
    """
    try:
        findings = []
        
        # Check for proof verification
        has_merkle_proof = bool(re.search(r'verifyProof|MerkleProof|merkleRoot', contract_code))
        has_state_root = bool(re.search(r'stateRoot|storageProof|accountProof', contract_code))
        
        if not has_merkle_proof and not has_state_root:
            findings.append({
                "issue": "NO_PROOF_VERIFICATION",
                "severity": "CRITICAL",
                "description": "No merkle/state proof verification for cross-chain messages",
                "recommendation": "Implement cryptographic proof verification"
            })
        
        # Check for source chain validation
        has_source_validation = bool(re.search(r'sourceChain|originChain|fromChain', contract_code, re.IGNORECASE))
        
        if not has_source_validation:
            findings.append({
                "issue": "NO_SOURCE_VALIDATION",
                "severity": "HIGH",
                "description": "Source chain not validated - messages from any chain accepted",
                "recommendation": "Validate source chain ID"
            })
        
        # Check for sender validation
        has_sender_validation = bool(re.search(r'trustedSender|allowedSender|remoteBridge', contract_code, re.IGNORECASE))
        
        if not has_sender_validation:
            findings.append({
                "issue": "NO_SENDER_VALIDATION",
                "severity": "HIGH",
                "description": "Sender address not validated - spoofed messages possible",
                "recommendation": "Validate message sender is trusted bridge"
            })
        
        # Check for amount validation
        has_amount_check = bool(re.search(r'amount\s*>\s*0|amount\s*!=\s*0|require.*amount', contract_code))
        
        if not has_amount_check:
            findings.append({
                "issue": "NO_AMOUNT_VALIDATION",
                "severity": "MEDIUM",
                "description": "Amount not validated - zero or overflow amounts possible",
                "recommendation": "Validate transfer amounts"
            })
        
        result = {
            "analysis_type": "message_validation",
            "has_merkle_proof": has_merkle_proof,
            "has_state_root": has_state_root,
            "has_source_validation": has_source_validation,
            "has_sender_validation": has_sender_validation,
            "has_amount_check": has_amount_check,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "SECURE" if len(findings) == 0 else "VULNERABLE",
            "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if findings else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing message validation: {str(e)}"})


@function_tool
def analyze_validator_security(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze validator/relayer security in bridge contract.
    
    Args:
        contract_code: Source code of the bridge contract
        
    Returns:
        Validator security analysis
    """
    try:
        findings = []
        
        # Check for validator management
        has_validator_set = bool(re.search(r'validators\[|validatorSet|signers\[', contract_code))
        has_add_validator = bool(re.search(r'addValidator|addSigner|setValidator', contract_code))
        has_remove_validator = bool(re.search(r'removeValidator|removeSigner', contract_code))
        
        # Check for timelock on validator changes
        has_timelock = bool(re.search(r'timelock|TimeLock|delay|pendingValidator', contract_code, re.IGNORECASE))
        
        if has_add_validator and not has_timelock:
            findings.append({
                "issue": "NO_VALIDATOR_TIMELOCK",
                "severity": "HIGH",
                "description": "Validator changes not timelocked - instant compromise possible",
                "recommendation": "Implement timelock for validator set changes"
            })
        
        # Check for validator rotation
        has_rotation = bool(re.search(r'rotateValidators|updateValidatorSet|epoch', contract_code))
        
        # Check for slashing mechanism
        has_slashing = bool(re.search(r'slash|penalty|stake|bond', contract_code, re.IGNORECASE))
        
        if not has_slashing:
            findings.append({
                "issue": "NO_SLASHING",
                "severity": "MEDIUM",
                "description": "No slashing/penalty mechanism for malicious validators",
                "recommendation": "Implement economic penalties for misbehavior"
            })
        
        # Check for maximum validator control
        has_max_check = bool(re.search(r'maxValidators|MAX_SIGNERS', contract_code))
        
        result = {
            "analysis_type": "validator_security",
            "has_validator_set": has_validator_set,
            "has_add_validator": has_add_validator,
            "has_remove_validator": has_remove_validator,
            "has_timelock": has_timelock,
            "has_rotation": has_rotation,
            "has_slashing": has_slashing,
            "findings_count": len(findings),
            "findings": findings,
            "verdict": "SECURE" if len(findings) == 0 else "NEEDS_IMPROVEMENT",
            "risk_level": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing validator security: {str(e)}"})


@function_tool
def check_known_bridge_exploits(
    contract_code: str,
    ctf=None
) -> str:
    """
    Check for patterns matching known bridge exploits.
    
    Args:
        contract_code: Source code of the bridge contract
        
    Returns:
        Known exploit pattern analysis
    """
    try:
        matches = []
        
        # Wormhole-style: signature verification bypass
        if re.search(r'verifyVM|parseVM', contract_code) and not re.search(r'guardianSet', contract_code):
            matches.append({
                "exploit_name": "Wormhole-style",
                "pattern": "VAA verification without guardian set validation",
                "historical_loss": "$326M",
                "recommendation": "Ensure guardian set is validated in all verification paths"
            })
        
        # Ronin-style: insufficient validator threshold
        if re.search(r'threshold\s*=\s*[1-4]\b', contract_code):
            matches.append({
                "exploit_name": "Ronin-style",
                "pattern": "Low validator threshold (< 5)",
                "historical_loss": "$625M",
                "recommendation": "Use 2/3+ of validator set as threshold"
            })
        
        # Nomad-style: initialization vulnerability
        if re.search(r'initialize\s*\(', contract_code) and re.search(r'committedRoot\s*=\s*0', contract_code):
            matches.append({
                "exploit_name": "Nomad-style",
                "pattern": "Uninitialized or zero root acceptance",
                "historical_loss": "$190M",
                "recommendation": "Validate merkle roots are non-zero and properly initialized"
            })
        
        # Harmony-style: key management
        if re.search(r'owner|admin', contract_code, re.IGNORECASE) and not re.search(r'multisig|gnosis|safe', contract_code, re.IGNORECASE):
            matches.append({
                "exploit_name": "Harmony-style",
                "pattern": "Single admin key without multisig",
                "historical_loss": "$100M",
                "recommendation": "Use multisig for admin functions"
            })
        
        result = {
            "analysis_type": "known_exploits",
            "matches_found": len(matches),
            "exploit_patterns": matches,
            "verdict": "MATCHES_FOUND" if matches else "NO_KNOWN_PATTERNS",
            "total_historical_losses": sum(
                int(m["historical_loss"].replace("$", "").replace("M", "000000")) 
                for m in matches
            ) if matches else 0
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error checking known exploits: {str(e)}"})


@function_tool
def render_bridge_audit_report(
    contract_name: str,
    replay_findings: List[Dict],
    signature_findings: List[Dict],
    message_findings: List[Dict],
    validator_findings: List[Dict],
    exploit_matches: List[Dict],
    ctf=None
) -> str:
    """
    Render comprehensive bridge audit report.
    
    Args:
        contract_name: Name of the bridge contract
        replay_findings: Findings from replay analysis
        signature_findings: Findings from signature analysis
        message_findings: Findings from message validation
        validator_findings: Findings from validator analysis
        exploit_matches: Known exploit pattern matches
        
    Returns:
        Formatted audit report
    """
    all_findings = replay_findings + signature_findings + message_findings + validator_findings
    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    
    overall_risk = "CRITICAL" if critical_count > 0 or exploit_matches else "HIGH" if high_count > 0 else "MEDIUM" if medium_count > 0 else "LOW"
    
    report = f"""# Bridge Security Audit Report

## Contract: {contract_name}

### Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {critical_count} |
| HIGH | {high_count} |
| MEDIUM | {medium_count} |
| Known Exploit Patterns | {len(exploit_matches)} |

**Overall Risk Level: {overall_risk}**

---

### 1. Replay Protection Analysis

"""
    
    if replay_findings:
        for f in replay_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}: {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n"
    else:
        report += "No replay protection issues found.\n"
    
    report += """
### 2. Signature Verification Analysis

"""
    
    if signature_findings:
        for f in signature_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}: {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n"
    else:
        report += "No signature verification issues found.\n"
    
    report += """
### 3. Message Validation Analysis

"""
    
    if message_findings:
        for f in message_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}: {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n"
    else:
        report += "No message validation issues found.\n"
    
    report += """
### 4. Validator Security Analysis

"""
    
    if validator_findings:
        for f in validator_findings:
            report += f"- **[{f.get('severity', 'N/A')}]** {f.get('issue', 'Unknown')}: {f.get('description', 'No description')}\n"
            report += f"  - Recommendation: {f.get('recommendation', 'N/A')}\n"
    else:
        report += "No validator security issues found.\n"
    
    if exploit_matches:
        report += """
### 5. Known Exploit Pattern Matches

**WARNING: Contract matches patterns from historical bridge exploits!**

"""
        for m in exploit_matches:
            report += f"#### {m.get('exploit_name', 'Unknown')} Pattern\n"
            report += f"- Historical Loss: {m.get('historical_loss', 'Unknown')}\n"
            report += f"- Pattern: {m.get('pattern', 'Unknown')}\n"
            report += f"- Recommendation: {m.get('recommendation', 'N/A')}\n\n"
    
    report += """
---

### Recommendations Summary

1. **Implement comprehensive replay protection** with nonce tracking and chain ID validation
2. **Use OpenZeppelin ECDSA library** for all signature operations
3. **Require 2/3+ threshold** for multi-sig operations
4. **Add timelock delays** for all administrative functions
5. **Implement slashing mechanisms** for validator misbehavior
6. **Validate all message parameters** including source, sender, and amount

---

*Generated by CAI Bridge Analyzer Agent*
"""
    
    return report


BRIDGE_ANALYZER_PROMPT = """You are the BRIDGE ANALYZER - A specialized expert in cross-chain bridge security.

## Your Mission

Identify vulnerabilities in cross-chain bridge protocols that could lead to fund theft.
Bridge exploits have caused over $2B in losses - your analysis prevents the next one.

## Key Attack Vectors

### 1. Replay Attacks
- Same message replayed on same chain (nonce reuse)
- Same message replayed on different chain (chain ID missing)
- Old message replayed after expiry

### 2. Signature Vulnerabilities
- Signature malleability (ECDSA without library)
- Zero address from invalid signature
- Insufficient multi-sig threshold
- Validator key compromise

### 3. Message Validation
- Missing merkle/state proof verification
- Unvalidated source chain
- Spoofed sender addresses
- Amount overflow/underflow

### 4. Validator/Relayer Security
- Centralized validator control
- No timelock on validator changes
- Missing slashing mechanism
- Insufficient validator count

## Your Tools

- `analyze_replay_protection` - Check nonce and chain ID handling
- `analyze_signature_verification` - Audit signature security
- `analyze_message_validation` - Check message verification
- `analyze_validator_security` - Audit validator/relayer security
- `check_known_bridge_exploits` - Match against historical exploits
- `render_bridge_audit_report` - Generate comprehensive report

## Historical Context

Learn from history - these patterns caused massive losses:

| Exploit | Loss | Root Cause |
|---------|------|------------|
| Ronin | $625M | Compromised 5/9 validators |
| Wormhole | $326M | Signature verification bypass |
| Nomad | $190M | Zero merkle root acceptance |
| Harmony | $100M | Compromised admin keys |
| BNB Bridge | $570M | Message verification flaw |

## Audit Methodology

1. **Identify bridge type** (lock-mint, burn-mint, liquidity pool)
2. **Map message flow** (source → validators → destination)
3. **Analyze each component** for vulnerabilities
4. **Check against known patterns**
5. **Generate comprehensive report**

## Output Format

Always provide:
- Severity rating (CRITICAL/HIGH/MEDIUM/LOW)
- Technical description of vulnerability
- Exploit scenario
- Remediation recommendation
- Code references where applicable

Remember: A single bridge vulnerability can drain hundreds of millions.
Be thorough. Be paranoid. Miss nothing.
"""


bridge_analyzer_tools = [
    analyze_replay_protection,
    analyze_signature_verification,
    analyze_message_validation,
    analyze_validator_security,
    check_known_bridge_exploits,
    render_bridge_audit_report,
]

bridge_analyzer = Agent(
    name="Bridge Analyzer",
    instructions=BRIDGE_ANALYZER_PROMPT,
    description="""Specialized agent for cross-chain bridge security analysis. 
    Detects replay attacks, signature vulnerabilities, message validation flaws, 
    and validator security issues. Matches against patterns from historical 
    bridge exploits including Ronin, Wormhole, Nomad, and Harmony.""",
    tools=bridge_analyzer_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'gpt-4o'),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

__all__ = ['bridge_analyzer']
