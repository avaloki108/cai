"""
L2/Rollup Security Analyzer - Layer 2 Protocol Security Analysis

Analyzes Layer 2 rollup protocols for security vulnerabilities including:
- Optimistic rollup challenge period exploits
- ZK rollup proof verification issues
- Sequencer centralization risks
- State root manipulation
- Force-inclusion edge cases
- Bridge vulnerability patterns
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool

load_dotenv()

api_key = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
    or os.getenv("ALIAS_API_KEY")
    or "sk-placeholder"
)


class RollupType(Enum):
    OPTIMISTIC = "optimistic"
    ZK_ROLLUP = "zk_rollup"
    VALIDIUM = "validium"
    VOLITION = "volition"
    UNKNOWN = "unknown"


@dataclass
class L2Vulnerability:
    """Represents an L2/rollup vulnerability"""
    vulnerability_type: str
    severity: str
    description: str
    location: str
    attack_vector: str
    mitigation: str
    rollup_type: RollupType


@function_tool
def detect_rollup_type(contract_code: str, ctf=None) -> str:
    """
    Detect the type of L2 rollup from contract code.
    
    Args:
        contract_code: Source code of the L1/L2 contracts
        
    Returns:
        JSON with rollup type classification
    """
    try:
        rollup_indicators = {
            RollupType.OPTIMISTIC: [
                "challengeperiod", "challengetimeout", "fraudproof",
                "disputegame", "asserter", "challenger", "optimistic"
            ],
            RollupType.ZK_ROLLUP: [
                "verifier", "proof", "groth16", "plonk", "stark",
                "zkrollup", "zkproof", "commitment", "merkleproof"
            ],
            RollupType.VALIDIUM: [
                "validium", "dataavailability", "dac", "offchaindata"
            ],
            RollupType.VOLITION: [
                "volition", "hybridmode", "validiummode"
            ]
        }
        
        detected_types = []
        code_lower = contract_code.lower()
        
        for rollup_type, indicators in rollup_indicators.items():
            match_count = sum(1 for ind in indicators if ind in code_lower)
            if match_count >= 2:
                detected_types.append({
                    "type": rollup_type.value,
                    "confidence": min(match_count / 2, 1.0),
                    "matched_indicators": [ind for ind in indicators if ind in code_lower]
                })
        
        # Sort by confidence
        detected_types.sort(key=lambda x: x["confidence"], reverse=True)
        
        result = {
            "detected_types": detected_types,
            "primary_type": detected_types[0]["type"] if detected_types else "unknown",
            "analysis_type": "rollup_detection"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error detecting rollup type: {str(e)}"})


@function_tool
def analyze_challenge_period(contract_code: str, ctf=None) -> str:
    """
    Analyze challenge period security for optimistic rollups.
    
    Args:
        contract_code: Source code of the rollup contracts
        
    Returns:
        JSON with challenge period vulnerability analysis
    """
    try:
        vulnerabilities = []
        
        # Check for challenge period configuration
        if "challengeperiod" in contract_code.lower() or "challengetimeout" in contract_code.lower():
            # Extract challenge period duration
            period_match = re.search(
                r"challenge(?:period|timeout).*?(d+)",
                contract_code.lower()
            )
            if period_match:
                period_blocks = int(period_match.group(1))
                
                if period_blocks < 4320:  # Less than ~18 hours at 15s blocks
                    vulnerabilities.append({
                        "type": "SHORT_CHALLENGE_PERIOD",
                        "severity": "HIGH",
                        "description": f"Challenge period of {period_blocks} blocks is very short",
                        "attack_vector": "Attackers can finalize fraudulent blocks before watchers can respond",
                        "mitigation": "Increase challenge period to at least 7 days"
                    })
                elif period_blocks > 40320:  # More than ~7 days
                    vulnerabilities.append({
                        "type": "LONG_CHALLENGE_PERIOD",
                        "severity": "LOW",
                        "description": f"Challenge period of {period_blocks} blocks is very long",
                        "attack_vector": "Users must wait long time for withdrawals",
                        "mitigation": "Balance security with UX - consider 3-7 days"
                    })
            
            # Check for challenge period manipulation
            if "setchallengeperiod" in contract_code.lower():
                if "onlyowner" not in contract_code.lower():
                    vulnerabilities.append({
                        "type": "MANIPULABLE_CHALLENGE_PERIOD",
                        "severity": "CRITICAL",
                        "description": "Challenge period can be changed without authorization",
                        "attack_vector": "Attacker can shorten challenge period before fraud",
                        "mitigation": "Add timelock and governance for parameter changes"
                    })
            
            # Check for watchtower incentives
            if "watcher" in contract_code.lower() or "validator" in contract_code.lower():
                if "reward" not in contract_code.lower() and "incentive" not in contract_code.lower():
                    vulnerabilities.append({
                        "type": "NO_WATCHTOWER_INCENTIVE",
                        "severity": "MEDIUM",
                        "description": "No visible incentives for watchers/validators",
                        "attack_vector": "Insufficient watchtower coverage leads to missed fraud",
                        "mitigation": "Implement economic incentives for successful challenges"
                    })
        
        # Check for fraud proof validation
        if "fraudproof" in contract_code.lower():
            if "verify" not in contract_code.lower():
                vulnerabilities.append({
                    "type": "UNVERIFIED_FRAUD_PROOF",
                    "severity": "CRITICAL",
                    "description": "Fraud proof submission without verification",
                    "attack_vector": "Anyone can submit invalid fraud proofs",
                    "mitigation": "Implement cryptographic fraud proof verification"
                })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "challenge_period"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing challenge period: {str(e)}"})


@function_tool
def analyze_sequencer_risks(contract_code: str, ctf=None) -> str:
    """
    Analyze sequencer centralization and security risks.
    
    Args:
        contract_code: Source code of the rollup contracts
        
    Returns:
        JSON with sequencer risk analysis
    """
    try:
        risks = []
        
        # Check for sequencer implementation
        if "sequencer" in contract_code.lower():
            # Check for single sequencer
            if "sequenceraddress" in contract_code.lower() or "thesequencer" in contract_code.lower():
                risks.append({
                    "type": "SINGLE_SEQUENCER",
                    "severity": "HIGH",
                    "description": "Single sequencer detected",
                    "attack_vector": "Censorship, transaction reordering, downtime",
                    "mitigation": "Implement decentralized sequencer set or fallback mechanism"
                })
            
            # Check for sequencer rotation
            if "rotatesequencer" not in contract_code.lower() and "changesequencer" not in contract_code.lower():
                risks.append({
                    "type": "NO_SEQUENCER_ROTATION",
                    "severity": "MEDIUM",
                    "description": "No sequencer rotation mechanism",
                    "attack_vector": "Long-term sequencer can become malicious",
                    "mitigation": "Implement periodic sequencer rotation"
                })
            
            # Check for forced transaction inclusion
            if "forceinclusion" not in contract_code.lower() and "forceinclude" not in contract_code.lower():
                risks.append({
                    "type": "NO_FORCE_INCLUSION",
                    "severity": "HIGH",
                    "description": "No force transaction inclusion mechanism",
                    "attack_vector": "Sequencer can censor transactions indefinitely",
                    "mitigation": "Allow users to force-include transactions on L1"
                })
            else:
                # Check for force inclusion delay
                force_match = re.search(
                    r"force(?:include|inclusion).*?delay.*?(d+)",
                    contract_code.lower()
                )
                if force_match:
                    delay = int(force_match.group(1))
                    if delay > 86400:  # More than 1 day
                        risks.append({
                            "type": "LONG_FORCE_INCLUSION_DELAY",
                            "severity": "MEDIUM",
                            "description": f"Force inclusion delay of {delay} seconds is long",
                            "attack_vector": "Users must wait long time to bypass censorship",
                            "mitigation": "Reduce delay to reasonable timeframe (few hours)"
                        })
            
            # Check for L1 fallback
            if "fallback" not in contract_code.lower():
                risks.append({
                    "type": "NO_L1_FALLBACK",
                    "severity": "MEDIUM",
                    "description": "No L1 fallback mechanism detected",
                    "attack_vector": "If sequencer goes down, no transaction processing",
                    "mitigation": "Implement L1 fallback for transaction processing"
                })
        
        return json.dumps({
            "risk_count": len(risks),
            "risks": risks,
            "analysis_type": "sequencer_risks"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing sequencer risks: {str(e)}"})


@function_tool
def analyze_zk_verification(contract_code: str, ctf=None) -> str:
    """
    Analyze ZK proof verification security.
    
    Args:
        contract_code: Source code of the ZK verifier contracts
        
    Returns:
        JSON with ZK verification analysis
    """
    try:
        vulnerabilities = []
        
        # Check for verifier implementation
        if "verifier" in contract_code.lower():
            # Check for proof system type
            proof_systems = ["groth16", "plonk", "stark", "bulletproof", "snark"]
            detected_systems = [ps for ps in proof_systems if ps in contract_code.lower()]
            
            # Check for pairing operations (Groth16)
            if "pairing" in contract_code.lower():
                # Check for proper G1/G2 point validation
                if "validateproof" not in contract_code.lower() and "checkproof" not in contract_code.lower():
                    vulnerabilities.append({
                        "type": "MISSING_PROOF_VALIDATION",
                        "severity": "CRITICAL",
                        "description": "ZK proof verification without proper validation",
                        "attack_vector": "Invalid proofs may be accepted",
                        "mitigation": "Implement comprehensive proof validation"
                    })
                
                # Check for overflow in pairing operations
                if "bn254" in contract_code.lower() or "altbn128" in contract_code.lower():
                    vulnerabilities.append({
                        "type": "PAIRING_CURVE_LIMITATIONS",
                        "severity": "LOW",
                        "description": "BN254/alt_bn128 curve has known limitations",
                        "attack_vector": "Future cryptographic advances may weaken security",
                        "mitigation": "Consider migration paths to stronger curves"
                    })
            
            # Check for verifying key updates
            if "verifyingkey" in contract_code.lower():
                if "setverifyingkey" in contract_code.lower():
                    if "onlyowner" not in contract_code.lower():
                        vulnerabilities.append({
                            "type": "UPDATABLE_VERIFYING_KEY",
                            "severity": "CRITICAL",
                            "description": "Verifying key can be updated without authorization",
                            "attack_vector": "Attacker can set malicious verifying key",
                            "mitigation": "Add governance controls for key updates"
                        })
            
            # Check for recursive proofs
            if "recursive" in contract_code.lower():
                vulnerabilities.append({
                    "type": "RECURSIVE_PROOF_COMPLEXITY",
                    "severity": "MEDIUM",
                    "description": "Recursive proof verification detected",
                    "attack_vector": "Complex verification may have edge cases",
                    "mitigation": "Thoroughly test all recursive verification paths"
                })
        
        return json.dumps({
            "detected_proof_systems": detected_systems if 'detected_systems' in dir() else [],
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "zk_verification"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing ZK verification: {str(e)}"})


@function_tool
def analyze_state_root_security(contract_code: str, ctf=None) -> str:
    """
    Analyze state root management and security.
    
    Args:
        contract_code: Source code of the state management contracts
        
    Returns:
        JSON with state root security analysis
    """
    try:
        vulnerabilities = []
        
        # Check for state root handling
        if "stateroot" in contract_code.lower() or "statecommitment" in contract_code.lower():
            # Check for state root update mechanism
            if "updatestateroot" in contract_code.lower() or "commitstate" in contract_code.lower():
                # Check for state root validation
                if "validate" not in contract_code.lower() and "verify" not in contract_code.lower():
                    vulnerabilities.append({
                        "type": "UNVALIDATED_STATE_ROOT",
                        "severity": "CRITICAL",
                        "description": "State root updates without validation",
                        "attack_vector": "Malicious operator can commit invalid state",
                        "mitigation": "Add state transition validation"
                    })
            
            # Check for state root history
            if "statehistory" not in contract_code.lower() and "previousroot" not in contract_code.lower():
                vulnerabilities.append({
                    "type": "NO_STATE_HISTORY",
                    "severity": "MEDIUM",
                    "description": "No state root history maintained",
                    "attack_vector": "Cannot detect state manipulation or replay",
                    "mitigation": "Maintain state root history for auditing"
                })
            
            # Check for delayed finality
            if "finalitydelay" in contract_code.lower():
                delay_match = re.search(r"finalitydelay.*?(d+)", contract_code.lower())
                if delay_match:
                    delay = int(delay_match.group(1))
                    if delay < 10:
                        vulnerabilities.append({
                            "type": "SHORT_FINALITY_DELAY",
                            "severity": "MEDIUM",
                            "description": f"Finality delay of {delay} blocks is short",
                            "attack_vector": "Chain reorgs can affect finalized state",
                            "mitigation": "Increase finality delay to at least 1 hour"
                        })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "state_root_security"
        })
    except Exception as e:
        return json.dumps({"error": f"Error analyzing state root security: {str(e)}"})


@function_tool
def check_l2_bridge_patterns(contract_code: str, ctf=None) -> str:
    """
    Check for common L2 bridge vulnerability patterns.
    
    Args:
        contract_code: Source code of the bridge contracts
        
    Returns:
        JSON with bridge vulnerability analysis
    """
    try:
        vulnerabilities = []
        
        # Check for bridge implementation
        code_lower = contract_code.lower()
        
        if "bridge" in code_lower or "crosschain" in code_lower:
            # Check for message authentication
            if "crossdomain" in code_lower or "xdomain" in code_lower:
                # Check for proper sender verification
                if "xDomainMessenger" in code_lower or "l1crossdomainmessenger" in code_lower:
                    vulnerabilities.append({
                        "type": "OPTIMISM_BRIDGE_PATTERN",
                        "severity": "INFO",
                        "description": "Optimism-style cross-domain messaging detected",
                        "attack_vector": "Known patterns: message replay, sender spoofing",
                        "mitigation": "Ensure proper nonce management and sender verification"
                    })
            
            # Check for withdrawal verification
            if "withdraw" in code_lower:
                if "merkleproof" not in code_lower and "inclusionproof" not in code_lower:
                    vulnerabilities.append({
                        "type": "UNVERIFIED_WITHDRAWAL",
                        "severity": "CRITICAL",
                        "description": "Withdrawals without merkle proof verification",
                        "attack_vector": "Users can withdraw more than deposited",
                        "mitigation": "Add merkle proof verification for all withdrawals"
                    })
            
            # Check for deposit finality
            if "deposit" in code_lower:
                if "finalize" in code_lower:
                    # Check for deposit finalization delay
                    vulnerabilities.append({
                        "type": "ASYNC_DEPOSIT_FINALIZATION",
                        "severity": "LOW",
                        "description": "Async deposit finalization detected",
                        "attack_vector": "Race conditions between deposit and finalization",
                        "mitigation": "Ensure proper event ordering and state management"
                    })
            
            # Check for known vulnerable patterns
            known_patterns = {
                "nomad": "Replica/Root chain pattern - verify domain ID",
                "layerzero": "LayerZero endpoint - verify ULN configuration",
                "wormhole": "Guardian set validation - verify guardian signatures",
                "axelar": "Gateway pattern - verify command execution",
                "ccip": "Chainlink CCIP - verify lane configuration"
            }
            
            for pattern, note in known_patterns.items():
                if pattern in code_lower:
                    vulnerabilities.append({
                        "type": f"KNOWN_BRIDGE_PATTERN_{pattern.upper()}",
                        "severity": "INFO",
                        "description": f"{pattern} bridge pattern detected",
                        "attack_vector": note,
                        "mitigation": "Review known vulnerability patterns for this bridge type"
                    })
        
        return json.dumps({
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_type": "l2_bridge_patterns"
        })
    except Exception as e:
        return json.dumps({"error": f"Error checking L2 bridge patterns: {str(e)}"})


# Create the agent
l2_analyzer_agent = Agent(
    name="L2 Rollup Security Analyzer",
    instructions="""You are an expert in Layer 2 rollup security. Your role is to:

1. **Detect Rollup Types**: Identify optimistic, ZK, validium, or hybrid rollups
2. **Analyze Challenge Periods**: Review optimistic rollup challenge mechanisms
3. **Assess Sequencer Risks**: Evaluate centralization and censorship risks
4. **Review ZK Verification**: Check proof verification security
5. **Validate State Roots**: Ensure state commitment integrity
6. **Check Bridge Patterns**: Identify known bridge vulnerability patterns

Key attack vectors:
- Challenge period manipulation (optimistic)
- Sequencer censorship and downtime
- ZK proof verification bypass
- State root manipulation
- Bridge message replay and spoofing

Provide severity ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO) and specific mitigations.""",
    tools=[
        detect_rollup_type,
        analyze_challenge_period,
        analyze_sequencer_risks,
        analyze_zk_verification,
        analyze_state_root_security,
        check_l2_bridge_patterns
    ],
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias1"),
        openai_client=AsyncOpenAI(
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=api_key
        )
    )
)

# Export for registration
l2_analyzer = l2_analyzer_agent
