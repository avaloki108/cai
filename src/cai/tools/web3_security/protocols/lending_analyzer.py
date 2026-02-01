"""
Lending Protocol Analyzer

Specialized analyzer for lending/borrowing protocols (Aave, Compound-style).

Focuses on:
- Oracle manipulation for liquidations
- Interest rate manipulation
- Collateral factor exploits
- Health factor bypass
- Bad debt creation
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re


@dataclass
class LendingVulnerability:
    """Represents a lending-specific vulnerability."""
    
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


class LendingAnalyzer:
    """Analyzer for lending protocol vulnerabilities."""
    
    CRITICAL_PATTERNS = [
        # Oracle vulnerabilities
        (r"getPrice\(\)|latestRoundData\(\)", "oracle_usage", "Oracle manipulation risk"),
        (r"\.value\s*\*\s*price", "price_multiplication", "Price used in value calculation"),
        
        # Liquidation issues
        (r"liquidate\(", "liquidation_function", "Liquidation logic present"),
        (r"healthFactor|collateralRatio", "health_calculation", "Health factor calculation"),
        
        # Interest rate
        (r"borrowRate|supplyRate", "interest_rate", "Interest rate calculation"),
        (r"utilizationRate", "utilization", "Utilization rate used"),
    ]
    
    def analyze(self, contract_code: str, contract_name: str = "Unknown") -> List[LendingVulnerability]:
        """
        Analyze a lending contract for protocol-specific vulnerabilities.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for oracle manipulation risks
        if "getprice" in code_lower or "latestrounddata" in code_lower:
            # Check if staleness is verified
            has_staleness_check = bool(re.search(r"timestamp|updatedat", code_lower))
            
            if not has_staleness_check:
                vulnerabilities.append(LendingVulnerability(
                    type="oracle_manipulation",
                    severity="CRITICAL",
                    description="Oracle price used without staleness check - can lead to stale price liquidations",
                    location=contract_name,
                    recommendations=[
                        "Add staleness check: require(block.timestamp - updatedAt < MAX_DELAY)",
                        "Use Chainlink's answer validation",
                        "Implement circuit breakers for price deviations"
                    ]
                ))
        
        # Check for liquidation vulnerabilities
        if "liquidat" in code_lower:
            # Check for flash loan protection
            has_flash_loan_protection = bool(re.search(r"nonreentrant|timelock|delay", code_lower))
            
            if not has_flash_loan_protection:
                vulnerabilities.append(LendingVulnerability(
                    type="flash_loan_liquidation",
                    severity="HIGH",
                    description="Liquidation may be vulnerable to flash loan attacks",
                    location=contract_name,
                    recommendations=[
                        "Use TWAP for liquidation price checks",
                        "Implement liquidation delays",
                        "Add flash loan detection"
                    ]
                ))
        
        # Check for interest rate manipulation
        if "utilizationrate" in code_lower or "borrowrate" in code_lower:
            # Check for rate caps
            has_rate_cap = bool(re.search(r"max.*rate|rate.*cap", code_lower))
            
            if not has_rate_cap:
                vulnerabilities.append(LendingVulnerability(
                    type="interest_rate_manipulation",
                    severity="MEDIUM",
                    description="Interest rates may not have proper caps - can lead to extreme rates",
                    location=contract_name,
                    recommendations=[
                        "Implement maximum borrow/supply rate caps",
                        "Add utilization rate limits",
                        "Use gradual rate adjustments"
                    ]
                ))
        
        # Check for collateral factor issues
        if "collateral" in code_lower:
            # Check for proper validation
            has_collateral_validation = bool(re.search(r"require.*collateral|assert.*collateral", code_lower))
            
            if not has_collateral_validation:
                vulnerabilities.append(LendingVulnerability(
                    type="collateral_validation",
                    severity="HIGH",
                    description="Collateral handling may lack proper validation",
                    location=contract_name,
                    recommendations=[
                        "Validate collateral amounts and ratios",
                        "Implement minimum collateralization ratios",
                        "Add collateral type whitelisting"
                    ]
                ))
        
        # Check for bad debt creation
        if "borrow" in code_lower:
            # Check for health factor validation
            has_health_check = bool(re.search(r"healthfactor|health.*check", code_lower))
            
            if not has_health_check:
                vulnerabilities.append(LendingVulnerability(
                    type="bad_debt_risk",
                    severity="CRITICAL",
                    description="Borrowing without health factor checks can create bad debt",
                    location=contract_name,
                    recommendations=[
                        "Implement health factor checks before borrowing",
                        "Add bad debt prevention mechanisms",
                        "Use safety buffers in collateralization"
                    ]
                ))
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[LendingVulnerability]) -> Dict[str, Any]:
        """Generate a comprehensive report of lending vulnerabilities."""
        critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in vulnerabilities if v.severity == "MEDIUM"]
        
        return {
            "protocol_type": "lending",
            "total_issues": len(vulnerabilities),
            "by_severity": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium)
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "summary": f"Found {len(critical)} critical, {len(high)} high, {len(medium)} medium severity issues"
        }


__all__ = ['LendingAnalyzer', 'LendingVulnerability']
