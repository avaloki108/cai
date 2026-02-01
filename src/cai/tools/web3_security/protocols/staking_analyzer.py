"""
Staking Protocol Analyzer

Specialized analyzer for staking/rewards protocols.

Focuses on:
- Reward calculation vulnerabilities
- Rounding errors in share calculations
- Early unstaking exploits
- Reward rate manipulation
- Accounting inconsistencies
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re


@dataclass
class StakingVulnerability:
    """Represents a staking-specific vulnerability."""
    
    type: str
    severity: str
    description: str
    location: str
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "recommendations": self.recommendations
        }


class StakingAnalyzer:
    """Analyzer for staking protocol vulnerabilities."""
    
    def analyze(self, contract_code: str, contract_name: str = "Unknown") -> List[StakingVulnerability]:
        """
        Analyze a staking contract for protocol-specific vulnerabilities.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for reward calculation issues
        if "reward" in code_lower:
            # Check for rounding errors
            has_precision_handling = bool(re.search(r"1e18|1e6|multiplier|precision", code_lower))
            
            if not has_precision_handling:
                vulnerabilities.append(StakingVulnerability(
                    type="reward_rounding_error",
                    severity="HIGH",
                    description="Reward calculations may suffer from precision loss/rounding errors",
                    location=contract_name,
                    recommendations=[
                        "Use high precision multipliers (1e18)",
                        "Round in user's favor for safety",
                        "Add dust amount handling"
                    ]
                ))
        
        # Check for rewardPerToken manipulation
        if "rewardpertoken" in code_lower:
            has_safe_math = bool(re.search(r"safemath|unchecked", code_lower))
            
            if "unchecked" in code_lower:
                vulnerabilities.append(StakingVulnerability(
                    type="rewardpertoken_overflow",
                    severity="CRITICAL",
                    description="rewardPerToken calculation uses unchecked math - overflow risk",
                    location=contract_name,
                    recommendations=[
                        "Remove unchecked blocks from reward calculations",
                        "Add overflow checks",
                        "Cap reward rates"
                    ]
                ))
        
        # Check for early unstaking exploits
        if "unstake" in code_lower or "withdraw" in code_lower:
            has_time_check = bool(re.search(r"staketime|timestamp.*stake|lockeduntil", code_lower))
            
            if not has_time_check and "stake" in code_lower:
                vulnerabilities.append(StakingVulnerability(
                    type="early_unstake_exploit",
                    severity="MEDIUM",
                    description="No minimum staking period - users can stake/unstake for instant rewards",
                    location=contract_name,
                    recommendations=[
                        "Implement minimum staking duration",
                        "Add unstaking penalties for early withdrawal",
                        "Use time-weighted rewards"
                    ]
                ))
        
        # Check for reward rate manipulation
        if "updatereward" in code_lower or "setreward" in code_lower:
            has_access_control = bool(re.search(r"onlyowner|onlyrole|require.*msg\.sender", code_lower))
            
            if not has_access_control:
                vulnerabilities.append(StakingVulnerability(
                    type="reward_rate_manipulation",
                    severity="CRITICAL",
                    description="Reward rate can be manipulated by unauthorized parties",
                    location=contract_name,
                    recommendations=[
                        "Add onlyOwner to reward rate updates",
                        "Implement timelock for rate changes",
                        "Use gradual rate adjustments"
                    ]
                ))
        
        # Check for first staker attack
        if "stake" in code_lower and "totalsupply" in code_lower:
            has_virtual_shares = bool(re.search(r"virtual|offset|bootstrap", code_lower))
            
            if not has_virtual_shares:
                vulnerabilities.append(StakingVulnerability(
                    type="first_staker_attack",
                    severity="HIGH",
                    description="First staker may manipulate share calculations - similar to ERC4626 inflation attack",
                    location=contract_name,
                    recommendations=[
                        "Add virtual shares offset",
                        "Bootstrap with initial deposit",
                        "Implement minimum deposit amounts"
                    ]
                ))
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[StakingVulnerability]) -> Dict[str, Any]:
        """Generate a comprehensive report of staking vulnerabilities."""
        critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in vulnerabilities if v.severity == "MEDIUM"]
        
        return {
            "protocol_type": "staking",
            "total_issues": len(vulnerabilities),
            "by_severity": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium)
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "summary": f"Found {len(critical)} critical, {len(high)} high, {len(medium)} medium severity issues"
        }


__all__ = ['StakingAnalyzer', 'StakingVulnerability']
