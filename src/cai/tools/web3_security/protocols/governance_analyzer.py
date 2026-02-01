"""
Governance Protocol Analyzer

Specialized analyzer for governance systems (OpenZeppelin Governor, custom).

Focuses on:
- Flash loan governance attacks
- Proposal manipulation
- Timelock bypass
- Quorum manipulation
- Vote delegation issues
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re


@dataclass
class GovernanceVulnerability:
    """Represents a governance-specific vulnerability."""
    
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


class GovernanceAnalyzer:
    """Analyzer for governance protocol vulnerabilities."""
    
    def analyze(self, contract_code: str, contract_name: str = "Unknown") -> List[GovernanceVulnerability]:
        """
        Analyze a governance contract for protocol-specific vulnerabilities.
        
        Args:
            contract_code: Solidity source code
            contract_name: Name of the contract
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        code_lower = contract_code.lower()
        
        # Check for flash loan governance attacks
        if "vote" in code_lower or "propose" in code_lower:
            uses_snapshot = bool(re.search(r"snapshot|checkpoint", code_lower))
            
            if not uses_snapshot:
                vulnerabilities.append(GovernanceVulnerability(
                    type="flash_loan_governance",
                    severity="CRITICAL",
                    description="Governance uses current balance instead of snapshots - vulnerable to flash loan attacks",
                    location=contract_name,
                    recommendations=[
                        "Use snapshot-based voting (ERC20Votes)",
                        "Implement proposal delays",
                        "Require minimum holding period"
                    ]
                ))
        
        # Check for timelock bypass
        if "timelock" in code_lower:
            has_delay_check = bool(re.search(r"require.*timestamp|require.*delay", code_lower))
            
            if not has_delay_check:
                vulnerabilities.append(GovernanceVulnerability(
                    type="timelock_bypass",
                    severity="HIGH",
                    description="Timelock may be bypassable - improper delay validation",
                    location=contract_name,
                    recommendations=[
                        "Enforce delay requirements in timelock",
                        "Validate timestamp properly",
                        "Use OpenZeppelin TimelockController"
                    ]
                ))
        
        # Check for quorum manipulation
        if "quorum" in code_lower:
            has_quorum_validation = bool(re.search(r"require.*quorum|quorum.*check", code_lower))
            
            if not has_quorum_validation:
                vulnerabilities.append(GovernanceVulnerability(
                    type="quorum_manipulation",
                    severity="HIGH",
                    description="Quorum requirements may be manipulable",
                    location=contract_name,
                    recommendations=[
                        "Use fixed or bounded quorum calculation",
                        "Implement quorum floors and ceilings",
                        "Validate against total supply at snapshot"
                    ]
                ))
        
        # Check for proposal griefing
        if "propose" in code_lower:
            has_proposal_threshold = bool(re.search(r"proposalthreshold|require.*balance", code_lower))
            
            if not has_proposal_threshold:
                vulnerabilities.append(GovernanceVulnerability(
                    type="proposal_griefing",
                    severity="MEDIUM",
                    description="Anyone can create proposals - may lead to spam/griefing",
                    location=contract_name,
                    recommendations=[
                        "Require minimum token balance for proposals",
                        "Implement proposal fees",
                        "Add proposal limits per address"
                    ]
                ))
        
        # Check for vote delegation issues
        if "delegate" in code_lower:
            has_delegation_limits = bool(re.search(r"maxdelegat|delegation.*limit", code_lower))
            
            if not has_delegation_limits:
                vulnerabilities.append(GovernanceVulnerability(
                    type="delegation_concentration",
                    severity="MEDIUM",
                    description="Unlimited delegation may lead to vote concentration",
                    location=contract_name,
                    recommendations=[
                        "Implement delegation limits",
                        "Add delegation revocation",
                        "Track delegation chains"
                    ]
                ))
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[GovernanceVulnerability]) -> Dict[str, Any]:
        """Generate a comprehensive report of governance vulnerabilities."""
        critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in vulnerabilities if v.severity == "MEDIUM"]
        
        return {
            "protocol_type": "governance",
            "total_issues": len(vulnerabilities),
            "by_severity": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium)
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "summary": f"Found {len(critical)} critical, {len(high)} high, {len(medium)} medium severity issues"
        }


__all__ = ['GovernanceAnalyzer', 'GovernanceVulnerability']
