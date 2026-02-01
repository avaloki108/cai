"""
AMM (Automated Market Maker) Protocol Analyzer

Specialized analyzer for AMM/DEX protocols (Uniswap, Curve, Balancer-style).

Focuses on:
- Slippage protection
- MEV/sandwich attacks
- Liquidity manipulation
- Price impact
- Reentrancy in swaps
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re


@dataclass
class AMMVulnerability:
    """Represents an AMM-specific vulnerability."""
    
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


class AMMAnalyzer:
    """Analyzer for AMM protocol vulnerabilities."""
    
    def analyze(self, contract_code: str, contract_name: str = "Unknown") -> List[AMMVulnerability]:
        """
        Analyze an AMM contract for protocol-specific vulnerabilities.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for slippage protection
        if "swap" in code_lower:
            has_slippage = bool(re.search(r"minout|minamount|amountoutmin", code_lower))
            
            if not has_slippage:
                vulnerabilities.append(AMMVulnerability(
                    type="missing_slippage_protection",
                    severity="HIGH",
                    description="Swap functions lack slippage protection - vulnerable to sandwich attacks",
                    location=contract_name,
                    recommendations=[
                        "Add amountOutMin parameter to swaps",
                        "Implement deadline checks",
                        "Add maximum slippage percentage"
                    ]
                ))
        
        # Check for deadline protection
        if "swap" in code_lower or "trade" in code_lower:
            has_deadline = bool(re.search(r"deadline|expires?at", code_lower))
            
            if not has_deadline:
                vulnerabilities.append(AMMVulnerability(
                    type="missing_deadline",
                    severity="MEDIUM",
                    description="Transactions lack deadline - can be executed at unfavorable times",
                    location=contract_name,
                    recommendations=[
                        "Add deadline parameter",
                        "Require block.timestamp <= deadline",
                        "Implement transaction expiry"
                    ]
                ))
        
        # Check for reentrancy in liquidity operations
        if "addliquidity" in code_lower or "removeliquidity" in code_lower:
            has_reentrancy_guard = bool(re.search(r"nonreentrant|reentrancy.*guard", code_lower))
            
            if not has_reentrancy_guard:
                vulnerabilities.append(AMMVulnerability(
                    type="liquidity_reentrancy",
                    severity="CRITICAL",
                    description="Liquidity operations vulnerable to reentrancy attacks",
                    location=contract_name,
                    recommendations=[
                        "Add ReentrancyGuard modifier",
                        "Follow checks-effects-interactions pattern",
                        "Update reserves before external calls"
                    ]
                ))
        
        # Check for K-value manipulation
        if "getreserves" in code_lower or "reserve0" in code_lower:
            has_k_check = bool(re.search(r"k\s*[<>=]|invariant", code_lower))
            
            if not has_k_check:
                vulnerabilities.append(AMMVulnerability(
                    type="k_value_manipulation",
                    severity="HIGH",
                    description="Missing K-value (constant product) validation",
                    location=contract_name,
                    recommendations=[
                        "Validate K = reserve0 * reserve1 after swaps",
                        "Implement invariant checks",
                        "Prevent K decrease"
                    ]
                ))
        
        # Check for price manipulation via spot price
        if "price" in code_lower and "reserve" in code_lower:
            uses_twap = bool(re.search(r"twap|timeweighted|cumulative", code_lower))
            
            if not uses_twap:
                vulnerabilities.append(AMMVulnerability(
                    type="spot_price_oracle",
                    severity="CRITICAL",
                    description="Using spot price instead of TWAP - manipulable by flash loans",
                    location=contract_name,
                    recommendations=[
                        "Implement TWAP oracle",
                        "Use Uniswap V3 TWAP observations",
                        "Add price deviation checks"
                    ]
                ))
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[AMMVulnerability]) -> Dict[str, Any]:
        """Generate a comprehensive report of AMM vulnerabilities."""
        critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in vulnerabilities if v.severity == "MEDIUM"]
        
        return {
            "protocol_type": "amm",
            "total_issues": len(vulnerabilities),
            "by_severity": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium)
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "summary": f"Found {len(critical)} critical, {len(high)} high, {len(medium)} medium severity issues"
        }


__all__ = ['AMMAnalyzer', 'AMMVulnerability']
