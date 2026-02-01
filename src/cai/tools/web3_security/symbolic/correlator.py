"""
Symbolic-Static Cross-Correlation

This module correlates findings from static analysis (Slither) with
symbolic execution results (Mythril/Oyente) to validate reachability
and boost confidence in findings.

When both tools agree on a vulnerability, confidence increases significantly.
"""

import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from cai.tools.web3_security.symbolic.constraint_analyzer import PathConstraint


class CorrelationType(Enum):
    """Types of correlation between static and symbolic findings."""
    LOCATION_MATCH = "location_match"  # Same contract+function
    PATH_CONFIRMED = "path_confirmed"   # Symbolic confirms reachability
    CONSTRAINT_MATCH = "constraint_match"  # Constraints match data flow
    NO_CORRELATION = "no_correlation"


@dataclass
class CorrelatedFinding:
    """A finding correlated across static and symbolic analysis."""
    
    # Static analysis finding
    static_finding: Dict[str, Any]
    static_tool: str
    
    # Symbolic execution result
    symbolic_constraints: List[PathConstraint]
    symbolic_tool: str
    
    # Correlation metadata
    correlation_type: CorrelationType
    correlation_score: float  # 0-1
    
    # Enhanced confidence
    base_confidence: float
    boosted_confidence: float
    confidence_boost: float
    
    # Reasoning
    correlation_reasoning: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "static_finding": self.static_finding,
            "static_tool": self.static_tool,
            "symbolic_tool": self.symbolic_tool,
            "correlation": {
                "type": self.correlation_type.value,
                "score": self.correlation_score,
                "reasoning": self.correlation_reasoning
            },
            "confidence": {
                "base": self.base_confidence,
                "boosted": self.boosted_confidence,
                "boost_amount": self.confidence_boost
            },
            "constraint_count": len(self.symbolic_constraints)
        }


class SymbolicStaticCorrelator:
    """
    Correlates static analysis findings with symbolic execution results.
    
    Provides enhanced confidence scores when both analyses agree.
    """
    
    # Confidence boost amounts based on correlation strength
    BOOST_STRONG_CORRELATION = 0.40  # Both agree on reachable vulnerability
    BOOST_LOCATION_MATCH = 0.20      # Same location, different methods
    BOOST_PARTIAL_MATCH = 0.10       # Weak correlation
    
    def __init__(self):
        """Initialize the correlator."""
        pass
    
    def correlate_findings(
        self,
        static_findings: List[Dict[str, Any]],
        symbolic_constraints: List[PathConstraint],
        correlation_threshold: float = 0.6
    ) -> List[CorrelatedFinding]:
        """
        Correlate static findings with symbolic constraints.
        
        Args:
            static_findings: Findings from static analysis (Slither, etc.)
            symbolic_constraints: Constraints from symbolic execution
            correlation_threshold: Minimum score to consider correlated
            
        Returns:
            List of CorrelatedFinding objects
        """
        correlated = []
        
        for finding in static_findings:
            # Try to find matching symbolic constraints
            matches = self._find_matching_constraints(
                finding,
                symbolic_constraints
            )
            
            if matches:
                # Analyze correlation
                correlation_type, score, reasoning = self._analyze_correlation(
                    finding,
                    matches
                )
                
                # Calculate confidence boost
                base_conf = self._extract_confidence(finding)
                boost = self._calculate_boost(correlation_type, score)
                boosted_conf = min(base_conf + boost, 1.0)
                
                # Create correlated finding
                corr_finding = CorrelatedFinding(
                    static_finding=finding,
                    static_tool=finding.get("tool", "unknown"),
                    symbolic_constraints=matches,
                    symbolic_tool=matches[0].source_tool if matches else "unknown",
                    correlation_type=correlation_type,
                    correlation_score=score,
                    base_confidence=base_conf,
                    boosted_confidence=boosted_conf,
                    confidence_boost=boost,
                    correlation_reasoning=reasoning
                )
                
                correlated.append(corr_finding)
        
        return correlated
    
    def _find_matching_constraints(
        self,
        finding: Dict[str, Any],
        constraints: List[PathConstraint]
    ) -> List[PathConstraint]:
        """
        Find symbolic constraints that match a static finding.
        
        Args:
            finding: Static analysis finding
            constraints: List of path constraints
            
        Returns:
            List of matching constraints
        """
        matches = []
        
        # Extract location from finding
        location = finding.get("location", {})
        if isinstance(location, str):
            # Parse location string like "Contract::function"
            parts = location.split("::")
            contract = parts[0] if len(parts) > 0 else ""
            function = parts[1] if len(parts) > 1 else ""
        elif isinstance(location, dict):
            contract = location.get("contract", "")
            function = location.get("function", "")
        else:
            contract = finding.get("contract", "")
            function = finding.get("function", "")
        
        # Find constraints in same location
        for constraint in constraints:
            if (constraint.contract == contract and 
                constraint.function == function):
                matches.append(constraint)
        
        return matches
    
    def _analyze_correlation(
        self,
        finding: Dict[str, Any],
        constraints: List[PathConstraint]
    ) -> Tuple[CorrelationType, float, str]:
        """
        Analyze the type and strength of correlation.
        
        Args:
            finding: Static finding
            constraints: Matching symbolic constraints
            
        Returns:
            (CorrelationType, score, reasoning)
        """
        if not constraints:
            return (
                CorrelationType.NO_CORRELATION,
                0.0,
                "No symbolic execution data for this location"
            )
        
        # Check for strong correlation: vulnerability type matches
        finding_type = finding.get("type", "").lower()
        
        # If symbolic execution found same vuln type
        if any("reentrancy" in finding_type and c.constraint_type == "call_argument" 
               for c in constraints):
            return (
                CorrelationType.PATH_CONFIRMED,
                0.9,
                "Symbolic execution confirms reachable reentrancy path"
            )
        
        # Check for constraint matches with data flow
        if any(c.affected_state_vars for c in constraints):
            return (
                CorrelationType.CONSTRAINT_MATCH,
                0.75,
                "Symbolic constraints match static data flow analysis"
            )
        
        # At least location matches
        if constraints:
            avg_feasibility = sum(c.feasibility_score for c in constraints) / len(constraints)
            return (
                CorrelationType.LOCATION_MATCH,
                avg_feasibility * 0.6,
                f"Symbolic execution explored same location ({len(constraints)} constraints)"
            )
        
        return (
            CorrelationType.NO_CORRELATION,
            0.0,
            "No meaningful correlation found"
        )
    
    def _calculate_boost(
        self,
        correlation_type: CorrelationType,
        score: float
    ) -> float:
        """
        Calculate confidence boost based on correlation.
        
        Args:
            correlation_type: Type of correlation
            score: Correlation score
            
        Returns:
            Confidence boost amount (0-1)
        """
        if correlation_type == CorrelationType.PATH_CONFIRMED:
            return self.BOOST_STRONG_CORRELATION * score
        elif correlation_type == CorrelationType.CONSTRAINT_MATCH:
            return self.BOOST_LOCATION_MATCH * score
        elif correlation_type == CorrelationType.LOCATION_MATCH:
            return self.BOOST_PARTIAL_MATCH * score
        else:
            return 0.0
    
    def _extract_confidence(self, finding: Dict[str, Any]) -> float:
        """Extract confidence score from finding."""
        confidence = finding.get("confidence", 0.5)
        
        if isinstance(confidence, str):
            conf_map = {"high": 0.85, "medium": 0.55, "low": 0.30}
            return conf_map.get(confidence.lower(), 0.5)
        
        return float(confidence)


def correlate_slither_mythril(
    slither_findings: List[Dict[str, Any]],
    mythril_output: Dict[str, Any]
) -> List[CorrelatedFinding]:
    """
    Convenience function to correlate Slither findings with Mythril results.
    
    Args:
        slither_findings: List of Slither findings
        mythril_output: Mythril JSON output
        
    Returns:
        List of correlated findings with boosted confidence
    """
    from cai.tools.web3_security.symbolic.constraint_analyzer import (
        extract_constraints_from_mythril
    )
    
    # Extract constraints from Mythril
    constraints = extract_constraints_from_mythril(mythril_output)
    
    # Correlate
    correlator = SymbolicStaticCorrelator()
    return correlator.correlate_findings(slither_findings, constraints)


__all__ = [
    'CorrelationType',
    'CorrelatedFinding',
    'SymbolicStaticCorrelator',
    'correlate_slither_mythril',
]
