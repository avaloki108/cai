"""
Autonomous Audit Coordinator for Aegis.

This module provides intelligent, adaptive audit capabilities that go beyond
simple tool chaining. It implements:

1. **Adaptive Analysis**: Adjusts tool selection based on project characteristics
2. **Hypothesis-Driven Exploration**: Generates attack hypotheses and tests them
3. **Finding-Driven Deep Dives**: Automatically investigates high-severity findings
4. **Pivot Logic**: Changes approach when stuck or when findings suggest new angles
5. **Grit Loop**: Persistent exploration until real vulnerabilities are found or
   hypothesis space is exhausted

The coordinator acts as an intelligent agent that makes decisions about:
- Which tools to run and in what order
- When to deep-dive vs. move on
- How to correlate findings across tools
- When to stop (confident coverage vs. diminishing returns)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.console import Console
from cai.util_cache import LRUCache


console = Console()

CODE_CACHE_MAX = int(os.getenv("CAI_CODE_CACHE_MAX", "200"))
CODE_CACHE_TTL_SEC = float(os.getenv("CAI_CODE_CACHE_TTL_SEC", "300"))


class FindingSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ProjectCharacteristic(Enum):
    """Detected project characteristics that influence tool selection."""
    HAS_VAULTS = "has_vaults"           # ERC4626, yield vaults
    HAS_AMM = "has_amm"                 # DEX, swaps, liquidity pools
    HAS_LENDING = "has_lending"          # Lending/borrowing protocols
    HAS_GOVERNANCE = "has_governance"    # Governance, voting, timelocks
    HAS_UPGRADES = "has_upgrades"        # Proxy patterns, upgradeable
    HAS_ORACLES = "has_oracles"          # Price feeds, oracle usage
    HAS_FLASH_LOANS = "has_flash_loans"  # Flash loan providers/receivers
    HAS_NFT = "has_nft"                  # ERC721/1155 handling
    HAS_STAKING = "has_staking"          # Staking, rewards
    HAS_BRIDGES = "has_bridges"          # Cross-chain, bridges
    HAS_CALLBACKS = "has_callbacks"      # Callbacks, hooks
    IS_MONOREPO = "is_monorepo"          # Multiple subprojects


@dataclass
class AttackHypothesis:
    """A testable hypothesis about a potential vulnerability."""
    id: str
    description: str
    target_contracts: List[str]
    target_functions: List[str]
    attack_vector: str  # reentrancy, access_control, oracle_manipulation, etc.
    preconditions: List[str]
    expected_impact: str
    tools_to_use: List[str]
    status: str = "pending"  # pending, testing, confirmed, disproven, blocked
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    disproof_reason: Optional[str] = None


@dataclass
class AuditState:
    """Tracks the current state of an autonomous audit."""
    project_path: Path
    output_dir: Path
    characteristics: Set[ProjectCharacteristic] = field(default_factory=set)
    hypotheses: List[AttackHypothesis] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tools_run: List[str] = field(default_factory=list)
    deep_dives_done: List[str] = field(default_factory=list)
    pivots_attempted: int = 0
    grit_score: float = 0.0
    coverage_estimate: float = 0.0
    stuck_count: int = 0
    last_high_confidence_finding: Optional[datetime] = None


class AutonomousAuditCoordinator:
    """
    Intelligent audit coordinator that makes adaptive decisions.
    
    Implements the Grit Loop:
    1. Map value flows and trust boundaries
    2. Write one concrete exploit hypothesis
    3. Build the smallest proof (mental model, then PoC)
    4. If it fails, extract why; update the model
    5. Pivot: new angle, new tool, or new contract seam
    6. Log evidence; keep a short list of next hypotheses
    """
    
    # Patterns to detect project characteristics
    CHARACTERISTIC_PATTERNS = {
        ProjectCharacteristic.HAS_VAULTS: [
            r"convertToAssets", r"convertToShares", r"ERC4626", r"vault", r"deposit.*shares",
        ],
        ProjectCharacteristic.HAS_AMM: [
            r"swap", r"addLiquidity", r"removeLiquidity", r"getAmountOut", r"getReserves",
            r"UniswapV2", r"UniswapV3", r"Curve", r"Balancer", r"pair\.sync",
        ],
        ProjectCharacteristic.HAS_LENDING: [
            r"borrow", r"repay", r"liquidat", r"collateral", r"healthFactor",
            r"Aave", r"Compound", r"lendingPool", r"interestRate",
        ],
        ProjectCharacteristic.HAS_GOVERNANCE: [
            r"propose", r"vote", r"execute", r"timelock", r"governor", r"quorum",
        ],
        ProjectCharacteristic.HAS_UPGRADES: [
            r"upgradeTo", r"implementation", r"proxy", r"delegatecall.*implementation",
            r"ERC1967", r"TransparentProxy", r"UUPS",
        ],
        ProjectCharacteristic.HAS_ORACLES: [
            r"latestRoundData", r"getPrice", r"oracle", r"priceFeed", r"Chainlink",
            r"TWAP", r"observation",
        ],
        ProjectCharacteristic.HAS_FLASH_LOANS: [
            r"flashLoan", r"flash.*callback", r"IERC3156", r"executeOperation",
        ],
        ProjectCharacteristic.HAS_NFT: [
            r"ERC721", r"ERC1155", r"onERC721Received", r"onERC1155Received",
            r"tokenURI", r"ownerOf",
        ],
        ProjectCharacteristic.HAS_STAKING: [
            r"stake", r"unstake", r"reward", r"earned", r"rewardPerToken",
        ],
        ProjectCharacteristic.HAS_BRIDGES: [
            r"bridge", r"crossChain", r"LayerZero", r"Axelar", r"Wormhole",
            r"sendMessage", r"receiveMessage",
        ],
        ProjectCharacteristic.HAS_CALLBACKS: [
            r"callback", r"hook", r"onFlashLoan", r"uniswapV2Call", r"uniswapV3.*Callback",
        ],
    }
    
    # Attack vectors relevant to each characteristic
    CHARACTERISTIC_ATTACK_VECTORS = {
        ProjectCharacteristic.HAS_VAULTS: [
            "first_depositor_attack", "inflation_attack", "share_rounding",
            "donation_attack", "vault_reentrancy",
        ],
        ProjectCharacteristic.HAS_AMM: [
            "sandwich_attack", "price_manipulation", "slippage_exploit",
            "flash_swap_attack", "liquidity_removal_attack",
        ],
        ProjectCharacteristic.HAS_LENDING: [
            "oracle_manipulation", "liquidation_exploit", "bad_debt",
            "interest_rate_manipulation", "collateral_factor_exploit",
        ],
        ProjectCharacteristic.HAS_GOVERNANCE: [
            "flash_loan_governance", "proposal_griefing", "timelock_bypass",
            "vote_manipulation", "quorum_manipulation",
        ],
        ProjectCharacteristic.HAS_UPGRADES: [
            "storage_collision", "initialization_exploit", "upgrade_hijack",
            "selfdestruct_attack", "implementation_takeover",
        ],
        ProjectCharacteristic.HAS_ORACLES: [
            "oracle_manipulation", "stale_price", "price_deviation",
            "twap_manipulation", "oracle_dos",
        ],
        ProjectCharacteristic.HAS_FLASH_LOANS: [
            "flash_loan_attack", "callback_reentrancy", "price_manipulation",
        ],
        ProjectCharacteristic.HAS_CALLBACKS: [
            "callback_reentrancy", "cross_function_reentrancy", "hook_manipulation",
        ],
    }
    
    # Tools most effective for each attack vector
    ATTACK_VECTOR_TOOLS = {
        "reentrancy": ["slither_mcp_analyze_reentrancy", "mythril", "echidna"],
        "first_depositor_attack": ["slither_mcp_analyze_erc4626", "echidna", "foundry"],
        "inflation_attack": ["slither_mcp_analyze_erc4626", "mythril"],
        "oracle_manipulation": ["slither_mcp_analyze_lending", "mythril", "foundry"],
        "sandwich_attack": ["slither_mcp_analyze_amm", "foundry"],
        "access_control": ["slither_mcp_analyze_access_control", "slither"],
        "cross_contract": ["slither_mcp_analyze_cross_contract", "mythril"],
        "flash_loan_attack": ["slither", "mythril", "foundry"],
        "callback_reentrancy": ["slither_mcp_analyze_reentrancy", "slither_mcp_analyze_cross_contract"],
    }
    
    def __init__(self, state: AuditState):
        self.state = state
        self._code_cache: LRUCache[str, str] = LRUCache(
            max_size=CODE_CACHE_MAX,
            ttl_seconds=CODE_CACHE_TTL_SEC,
        )
    
    async def analyze_project_characteristics(self, contract_files: List[Path]) -> Set[ProjectCharacteristic]:
        """
        Analyze project source code to detect characteristics that influence tool selection.
        """
        console.print("[bold cyan]🔍 Analyzing project characteristics...[/bold cyan]")
        
        characteristics: Set[ProjectCharacteristic] = set()
        
        # Cache and analyze code
        for sol_file in contract_files[:50]:  # Limit to first 50 files
            try:
                code = sol_file.read_text(encoding="utf-8", errors="ignore")
                self._code_cache.set(str(sol_file), code)
                
                for char, patterns in self.CHARACTERISTIC_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, code, re.IGNORECASE):
                            characteristics.add(char)
                            break
            except Exception:
                pass
        
        # Check for monorepo
        if len(list(self.state.project_path.glob("*/foundry.toml"))) > 1:
            characteristics.add(ProjectCharacteristic.IS_MONOREPO)
        
        self.state.characteristics = characteristics
        
        # Log detected characteristics
        if characteristics:
            console.print(f"[green]  Detected: {', '.join(c.value for c in characteristics)}[/green]")
        else:
            console.print("[yellow]  No specific characteristics detected - will run general analysis[/yellow]")
        
        return characteristics
    
    def generate_hypotheses(self) -> List[AttackHypothesis]:
        """
        Generate attack hypotheses based on project characteristics and initial findings.
        """
        console.print("[bold cyan]💡 Generating attack hypotheses...[/bold cyan]")
        
        hypotheses: List[AttackHypothesis] = []
        
        # Generate hypotheses based on characteristics
        for char in self.state.characteristics:
            attack_vectors = self.CHARACTERISTIC_ATTACK_VECTORS.get(char, [])
            
            for vector in attack_vectors:
                # Find relevant contracts
                target_contracts = self._find_contracts_for_vector(vector)
                if not target_contracts:
                    continue
                
                tools = self.ATTACK_VECTOR_TOOLS.get(vector, ["slither", "mythril"])
                
                hypothesis = AttackHypothesis(
                    id=f"{char.value}_{vector}_{len(hypotheses)}",
                    description=f"Test for {vector} vulnerability in {char.value} pattern",
                    target_contracts=target_contracts,
                    target_functions=self._find_functions_for_vector(vector, target_contracts),
                    attack_vector=vector,
                    preconditions=self._get_preconditions_for_vector(vector),
                    expected_impact=self._get_expected_impact(vector),
                    tools_to_use=tools,
                )
                hypotheses.append(hypothesis)
        
        # Add hypotheses based on existing findings
        for finding in self.state.findings:
            if finding.get("severity") in ["Critical", "High"]:
                # Generate follow-up hypothesis
                hypothesis = self._hypothesis_from_finding(finding)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        # Always add general hypotheses
        hypotheses.extend(self._generate_general_hypotheses())
        
        self.state.hypotheses = hypotheses
        console.print(f"[green]  Generated {len(hypotheses)} hypotheses to test[/green]")
        
        return hypotheses
    
    def _find_contracts_for_vector(self, vector: str) -> List[str]:
        """Find contracts that might be vulnerable to a specific attack vector."""
        contracts = []
        
        vector_patterns = {
            "first_depositor_attack": [r"deposit", r"mint.*shares"],
            "inflation_attack": [r"convertTo", r"previewDeposit"],
            "oracle_manipulation": [r"getPrice", r"latestRoundData"],
            "sandwich_attack": [r"swap", r"exchange"],
            "reentrancy": [r"\.call\{", r"transfer\(", r"send\("],
            "access_control": [r"onlyOwner", r"require.*msg\.sender"],
        }
        
        patterns = vector_patterns.get(vector, [])
        
        for file_path, code in self._code_cache.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    contracts.append(Path(file_path).stem)
                    break
        
        return contracts[:5]  # Limit to top 5
    
    def _find_functions_for_vector(self, vector: str, contracts: List[str]) -> List[str]:
        """Find functions relevant to an attack vector."""
        function_patterns = {
            "first_depositor_attack": ["deposit", "mint"],
            "inflation_attack": ["convertToShares", "convertToAssets", "previewDeposit"],
            "oracle_manipulation": ["getPrice", "updatePrice", "setOracle"],
            "sandwich_attack": ["swap", "swapExactTokensForTokens"],
            "reentrancy": ["withdraw", "transfer", "claim"],
            "access_control": ["setOwner", "transferOwnership", "upgrade"],
        }
        return function_patterns.get(vector, [])
    
    def _get_preconditions_for_vector(self, vector: str) -> List[str]:
        """Get preconditions that must be true for the attack to work."""
        preconditions = {
            "first_depositor_attack": [
                "Vault has zero total assets",
                "Attacker can be first depositor",
                "No virtual assets/shares offset",
            ],
            "oracle_manipulation": [
                "Oracle can be influenced (spot price, TWAP)",
                "No staleness check or check is insufficient",
                "Price deviation not validated",
            ],
            "reentrancy": [
                "External call before state update",
                "No reentrancy guard",
                "Attacker-controlled callback",
            ],
            "sandwich_attack": [
                "No slippage protection",
                "No deadline check",
                "Transaction visible in mempool",
            ],
        }
        return preconditions.get(vector, ["Unknown preconditions"])
    
    def _get_expected_impact(self, vector: str) -> str:
        """Get expected impact of a successful attack."""
        impacts = {
            "first_depositor_attack": "Theft of first depositor funds through share manipulation",
            "inflation_attack": "Theft of vault assets through inflated share price",
            "oracle_manipulation": "Incorrect pricing leading to bad debt or theft",
            "sandwich_attack": "MEV extraction from user trades",
            "reentrancy": "Unauthorized withdrawal of funds",
            "access_control": "Unauthorized privileged operations",
        }
        return impacts.get(vector, "Unknown impact")
    
    def _hypothesis_from_finding(self, finding: Dict[str, Any]) -> Optional[AttackHypothesis]:
        """Generate a follow-up hypothesis from an existing finding."""
        finding_type = finding.get("type", "").lower()
        
        # Map finding types to deeper investigation hypotheses
        if "reentrancy" in finding_type:
            return AttackHypothesis(
                id=f"deepdive_reentrancy_{len(self.state.hypotheses)}",
                description=f"Deep dive: Exploit reentrancy in {finding.get('location', 'unknown')}",
                target_contracts=[finding.get("location", "").split("::")[0]],
                target_functions=[finding.get("location", "").split("::")[-1]],
                attack_vector="reentrancy_exploit",
                preconditions=["Confirmed reentrancy pattern exists"],
                expected_impact="Direct fund theft if exploitable",
                tools_to_use=["mythril", "foundry", "echidna"],
            )
        
        return None
    
    def _generate_general_hypotheses(self) -> List[AttackHypothesis]:
        """Generate hypotheses that apply to any project."""
        return [
            AttackHypothesis(
                id="general_reentrancy",
                description="Check all external calls for reentrancy vulnerabilities",
                target_contracts=[],
                target_functions=["*"],
                attack_vector="reentrancy",
                preconditions=["External calls exist"],
                expected_impact="Potential fund theft",
                tools_to_use=["slither", "mythril", "slither_mcp"],
            ),
            AttackHypothesis(
                id="general_unchecked_calls",
                description="Check for unchecked return values from external calls",
                target_contracts=[],
                target_functions=["*"],
                attack_vector="unchecked_call",
                preconditions=["External calls exist"],
                expected_impact="Silent failures leading to state corruption",
                tools_to_use=["slither", "mythril"],
            ),
            AttackHypothesis(
                id="general_arithmetic",
                description="Check for arithmetic overflow/underflow issues",
                target_contracts=[],
                target_functions=["*"],
                attack_vector="arithmetic",
                preconditions=["Arithmetic operations exist"],
                expected_impact="Incorrect calculations, fund theft",
                tools_to_use=["slither", "mythril"],
            ),
            AttackHypothesis(
                id="general_access_control",
                description="Check privileged functions for missing access controls",
                target_contracts=[],
                target_functions=["*"],
                attack_vector="access_control",
                preconditions=["Privileged functions exist"],
                expected_impact="Unauthorized operations",
                tools_to_use=["slither_mcp_analyze_access_control", "slither"],
            ),
        ]
    
    def prioritize_tools(self) -> List[str]:
        """
        Determine which tools to run and in what order based on project characteristics.
        """
        console.print("[bold cyan]📊 Prioritizing analysis tools...[/bold cyan]")
        
        # Base tools always run
        priority_tools = ["slither_mcp", "slither"]
        
        # Add tools based on characteristics
        char_tool_map = {
            ProjectCharacteristic.HAS_VAULTS: ["slither_mcp_analyze_erc4626", "echidna"],
            ProjectCharacteristic.HAS_AMM: ["slither_mcp_analyze_amm", "foundry"],
            ProjectCharacteristic.HAS_LENDING: ["slither_mcp_analyze_lending", "mythril"],
            ProjectCharacteristic.HAS_UPGRADES: ["slither", "mythril"],  # Extra proxy checks
            ProjectCharacteristic.HAS_ORACLES: ["mythril", "foundry"],
            ProjectCharacteristic.HAS_CALLBACKS: ["slither_mcp_analyze_cross_contract", "echidna"],
            ProjectCharacteristic.HAS_GOVERNANCE: ["foundry", "mythril"],
        }
        
        for char in self.state.characteristics:
            tools = char_tool_map.get(char, [])
            for tool in tools:
                if tool not in priority_tools:
                    priority_tools.append(tool)
        
        # Always add cross-contract analysis
        if "slither_mcp_analyze_cross_contract" not in priority_tools:
            priority_tools.append("slither_mcp_analyze_cross_contract")
        
        # Add fuzzing tools if not already present
        if "echidna" not in priority_tools:
            priority_tools.append("echidna")
        if "medusa" not in priority_tools:
            priority_tools.append("medusa")
        
        console.print(f"[green]  Tool priority: {' → '.join(priority_tools[:8])}...[/green]")
        
        return priority_tools
    
    def should_deep_dive(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Decide whether a finding warrants a deep dive investigation.
        
        Returns (should_dive, reason)
        """
        severity = finding.get("severity", "").lower()
        confidence = finding.get("confidence", "").lower()
        finding_type = finding.get("type", "").lower()
        
        # Critical findings always warrant deep dive
        if severity == "critical":
            return True, "Critical severity finding - investigating for exploitability"
        
        # High severity + high confidence
        if severity == "high" and confidence in ["high", "medium"]:
            return True, "High severity with good confidence - investigating"
        
        # Specific types that are often exploitable
        high_value_types = [
            "reentrancy", "arbitrary-send", "unprotected-upgrade",
            "oracle", "flash-loan", "access-control",
        ]
        for hv_type in high_value_types:
            if hv_type in finding_type:
                return True, f"High-value vulnerability type ({hv_type}) - investigating"
        
        # Multiple findings in same location suggest complex issue
        location = finding.get("location", "")
        same_location_count = sum(
            1 for f in self.state.findings
            if f.get("location") == location
        )
        if same_location_count >= 3:
            return True, "Multiple findings in same location - investigating for root cause"
        
        return False, "Does not meet deep dive criteria"
    
    def should_pivot(self) -> Tuple[bool, str, str]:
        """
        Decide whether to pivot to a different approach.
        
        Returns (should_pivot, reason, suggested_direction)
        """
        # Check if stuck (no high-confidence findings after multiple tools)
        if len(self.state.tools_run) >= 3:
            recent_high_confidence = any(
                f.get("confidence", "").lower() == "high"
                for f in self.state.findings[-10:]
            )
            if not recent_high_confidence:
                self.state.stuck_count += 1
                
                if self.state.stuck_count >= 2:
                    # Suggest pivot
                    untested_vectors = self._get_untested_attack_vectors()
                    if untested_vectors:
                        return True, "No high-confidence findings after multiple tools", f"Try {untested_vectors[0]} angle"
                    
                    # Suggest deeper analysis on existing findings
                    if self.state.findings:
                        return True, "Stuck - trying deeper analysis on existing findings", "deep_dive_existing"
        
        # Check hypothesis coverage
        tested_hypotheses = [h for h in self.state.hypotheses if h.status != "pending"]
        if len(tested_hypotheses) >= 5 and not any(h.status == "confirmed" for h in tested_hypotheses):
            return True, "Multiple hypotheses disproven - need new angle", "generate_new_hypotheses"
        
        return False, "", ""
    
    def _get_untested_attack_vectors(self) -> List[str]:
        """Get attack vectors that haven't been tested yet."""
        tested_vectors = {h.attack_vector for h in self.state.hypotheses if h.status != "pending"}
        all_vectors = set()
        for vectors in self.CHARACTERISTIC_ATTACK_VECTORS.values():
            all_vectors.update(vectors)
        
        return list(all_vectors - tested_vectors)
    
    def update_hypothesis_status(
        self,
        hypothesis_id: str,
        status: str,
        confidence: float,
        evidence: List[str],
        disproof_reason: Optional[str] = None
    ):
        """Update the status of a hypothesis based on testing results."""
        for h in self.state.hypotheses:
            if h.id == hypothesis_id:
                h.status = status
                h.confidence = confidence
                h.evidence.extend(evidence)
                h.disproof_reason = disproof_reason
                
                # Update grit score
                self.state.pivots_attempted += 1
                if status == "confirmed":
                    self.state.grit_score += 10
                    self.state.last_high_confidence_finding = datetime.now()
                elif status == "disproven":
                    self.state.grit_score += 1  # Small reward for thorough testing
                
                break
    
    def calculate_coverage_estimate(self) -> float:
        """Estimate how much of the attack surface has been covered."""
        if not self.state.hypotheses:
            return 0.0
        
        tested = sum(1 for h in self.state.hypotheses if h.status != "pending")
        total = len(self.state.hypotheses)
        
        # Base coverage from hypothesis testing
        coverage = (tested / total) * 0.6
        
        # Bonus for tool diversity
        unique_tools = len(set(self.state.tools_run))
        coverage += min(unique_tools * 0.05, 0.2)
        
        # Bonus for deep dives
        coverage += min(len(self.state.deep_dives_done) * 0.02, 0.1)
        
        # Bonus for confirmed findings (shows we're finding things)
        confirmed = sum(1 for h in self.state.hypotheses if h.status == "confirmed")
        coverage += min(confirmed * 0.05, 0.1)
        
        self.state.coverage_estimate = min(coverage, 1.0)
        return self.state.coverage_estimate
    
    def should_stop(self) -> Tuple[bool, str]:
        """
        Decide whether to stop the audit.
        
        Returns (should_stop, reason)
        """
        coverage = self.calculate_coverage_estimate()
        
        # Stop if we have good coverage and confirmed critical findings
        critical_confirmed = any(
            h.status == "confirmed" and "critical" in h.expected_impact.lower()
            for h in self.state.hypotheses
        )
        if coverage >= 0.8 and critical_confirmed:
            return True, f"High coverage ({coverage:.0%}) with confirmed critical findings"
        
        # Stop if all hypotheses tested and no high-value findings
        all_tested = all(h.status != "pending" for h in self.state.hypotheses)
        if all_tested and len(self.state.hypotheses) >= 10:
            return True, "All hypotheses tested - producing exhaustion proof"
        
        # Stop if stuck for too long
        if self.state.stuck_count >= 5:
            return True, "Stuck for too long - producing exhaustion proof"
        
        return False, ""
    
    def generate_exhaustion_proof(self) -> Dict[str, Any]:
        """
        Generate a proof of exhaustive testing when no exploits found.
        
        This documents what was checked and why we believe it's safe.
        """
        return {
            "type": "exhaustion_proof",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": "Comprehensive analysis completed without finding exploitable vulnerabilities",
            "coverage": {
                "estimate": f"{self.state.coverage_estimate:.0%}",
                "tools_run": self.state.tools_run,
                "hypotheses_tested": len([h for h in self.state.hypotheses if h.status != "pending"]),
                "deep_dives_completed": len(self.state.deep_dives_done),
                "pivots_attempted": self.state.pivots_attempted,
            },
            "hypotheses": [
                {
                    "id": h.id,
                    "description": h.description,
                    "status": h.status,
                    "confidence": h.confidence,
                    "disproof_reason": h.disproof_reason,
                }
                for h in self.state.hypotheses
            ],
            "characteristics_analyzed": [c.value for c in self.state.characteristics],
            "attack_vectors_checked": list(set(h.attack_vector for h in self.state.hypotheses)),
            "grit_score": self.state.grit_score,
            "confidence_in_safety": self._calculate_safety_confidence(),
        }
    
    def _calculate_safety_confidence(self) -> str:
        """Calculate confidence that the codebase is safe."""
        coverage = self.state.coverage_estimate
        tools_run = len(set(self.state.tools_run))
        hypotheses_tested = len([h for h in self.state.hypotheses if h.status != "pending"])
        
        score = (coverage * 40) + (min(tools_run, 8) * 5) + (min(hypotheses_tested, 10) * 2)
        
        if score >= 80:
            return "High - Comprehensive analysis with multiple tools and hypotheses"
        elif score >= 60:
            return "Medium - Good coverage but some attack vectors may need more testing"
        elif score >= 40:
            return "Low - Basic analysis completed, recommend additional review"
        else:
            return "Minimal - Limited analysis, manual review strongly recommended"
    
    def get_decision_log(self) -> List[Dict[str, Any]]:
        """Get a log of all autonomous decisions made during the audit."""
        return [
            {
                "type": "characteristic_detection",
                "characteristics": [c.value for c in self.state.characteristics],
            },
            {
                "type": "hypothesis_generation",
                "count": len(self.state.hypotheses),
                "attack_vectors": list(set(h.attack_vector for h in self.state.hypotheses)),
            },
            {
                "type": "tool_prioritization",
                "tools": self.state.tools_run,
            },
            {
                "type": "deep_dives",
                "locations": self.state.deep_dives_done,
            },
            {
                "type": "pivots",
                "count": self.state.pivots_attempted,
                "stuck_count": self.state.stuck_count,
            },
            {
                "type": "coverage",
                "estimate": f"{self.state.coverage_estimate:.0%}",
                "grit_score": self.state.grit_score,
            },
        ]


def create_coordinator(project_path: Path, output_dir: Path) -> AutonomousAuditCoordinator:
    """Create a new autonomous audit coordinator."""
    state = AuditState(project_path=project_path, output_dir=output_dir)
    return AutonomousAuditCoordinator(state)
