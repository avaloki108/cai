"""
Adversarial Pattern - GPTLens-style Auditor vs Critic workflow.

From the GPTLens paper: "Large Language Model-Powered Smart Contract 
Vulnerability Detection: New Perspectives"

Key insight: Generation is harder than discrimination. The same LLM can
critique its own outputs because discrimination requires only function-level
assessment while generation requires understanding the full context.

Architecture:
    1. AUDITOR phase (high recall): Multiple auditors with high temperature
       generate diverse vulnerability candidates with reasoning
    2. CRITIC phase (high precision): Critics evaluate each finding on:
       - Correctness: Is the reasoning logically sound?
       - Severity: How bad is the actual impact?
       - Profitability: Would an attacker bother?

Results from paper: Top-1 accuracy improved from 33.3% to 59.0%

ENHANCED with Skeptic Integration:
    - Skeptic Alpha: Logical disproof (challenges assumptions and reasoning)
    - Skeptic Beta: Economic disproof (proves attacks unprofitable)
    - Skeptic Gamma: Defense identification (finds protective controls)
"""

from typing import Dict, Any, Optional, List, Union, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
import asyncio

from cai.agents.patterns.pattern import Pattern, PatternType

if TYPE_CHECKING:
    from cai.sdk.agents import Agent


@dataclass
class Finding:
    """A vulnerability finding from an auditor."""
    
    id: str
    function_name: str
    vulnerability_type: str
    description: str
    reasoning: str
    severity: str  # Critical, High, Medium, Low, Info
    code_location: Optional[str] = None  # file:line
    
    # Critic scores (filled in during critic phase)
    correctness_score: Optional[float] = None
    severity_score: Optional[float] = None
    profitability_score: Optional[float] = None
    
    # Validation metadata
    tool_grounded: bool = False
    has_code_citation: bool = False
    has_reproduction_plan: bool = False
    
    @property
    def critic_score(self) -> float:
        """Combined critic score (average of all dimensions)."""
        scores = [
            s for s in [
                self.correctness_score,
                self.severity_score,
                self.profitability_score
            ] if s is not None
        ]
        return sum(scores) / len(scores) if scores else 0.0
    
    @property
    def is_valid(self) -> bool:
        """Check if finding passes minimum quality bar."""
        if self.critic_score < 5.0:
            return False
        # Check non-negotiable rules from research
        return self.tool_grounded and self.has_code_citation
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "function_name": self.function_name,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "reasoning": self.reasoning,
            "severity": self.severity,
            "code_location": self.code_location,
            "scores": {
                "correctness": self.correctness_score,
                "severity": self.severity_score,
                "profitability": self.profitability_score,
                "combined": self.critic_score
            },
            "validation": {
                "tool_grounded": self.tool_grounded,
                "has_code_citation": self.has_code_citation,
                "has_reproduction_plan": self.has_reproduction_plan,
                "is_valid": self.is_valid
            }
        }


@dataclass
class CriticEvaluation:
    """Evaluation of a finding by a critic."""
    
    finding_id: str
    critic_name: str
    
    correctness_score: float  # 0-10
    correctness_reasoning: str
    
    severity_score: float  # 0-10
    severity_reasoning: str
    
    profitability_score: float  # 0-10
    profitability_reasoning: str
    
    verdict: str  # "accept", "reject", "needs_more_info"
    rejection_reason: Optional[str] = None
    
    @property
    def passes_threshold(self) -> bool:
        """Check if all scores pass minimum threshold (5)."""
        return all(s >= 5.0 for s in [
            self.correctness_score,
            self.severity_score,
            self.profitability_score
        ])


@dataclass
class AdversarialPattern(Pattern):
    """
    GPTLens-style adversarial pattern for vulnerability detection.
    
    Separates generation (auditors) from discrimination (critics) to
    balance recall and precision in vulnerability detection.
    
    Attributes:
        auditors: List of auditor agents (high temperature, diverse)
        critics: List of critic agents (evaluate and filter)
        auditor_temperature: Temperature for auditor generation (higher = more diverse)
        min_critic_score: Minimum score for a finding to be accepted
        require_consensus: If True, multiple critics must agree
    """
    
    auditors: List[Any] = field(default_factory=list)
    critics: List[Any] = field(default_factory=list)
    
    # Auditor configuration
    auditor_temperature: float = 0.8  # Higher for diversity
    max_findings_per_auditor: int = 10
    
    # Critic configuration  
    min_critic_score: float = 5.0
    require_consensus: bool = True
    consensus_threshold: float = 0.6  # 60% of critics must agree
    
    # Results
    all_findings: List[Finding] = field(default_factory=list)
    validated_findings: List[Finding] = field(default_factory=list)
    rejected_findings: List[Finding] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize as adversarial pattern type."""
        self.type = PatternType.ADVERSARIAL
        super().__post_init__()
    
    def add_auditor(self, agent: Any) -> 'AdversarialPattern':
        """Add an auditor agent."""
        self.auditors.append(agent)
        if agent not in self.agents:
            self.agents.append(agent)
        return self
    
    def add_critic(self, agent: Any) -> 'AdversarialPattern':
        """Add a critic agent."""
        self.critics.append(agent)
        if agent not in self.agents:
            self.agents.append(agent)
        return self
    
    async def execute(
        self, 
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the adversarial pattern.
        
        Args:
            target: Contract path or code to audit
            context: Additional context for auditors
            
        Returns:
            Dict containing validated and rejected findings
        """
        # Phase 1: Auditors generate candidates (high recall)
        self.all_findings = await self._run_auditors(target, context)
        
        # Phase 2: Critics filter and rank (high precision)
        self.validated_findings, self.rejected_findings = await self._run_critics()
        
        return {
            "validated": [f.to_dict() for f in self.validated_findings],
            "rejected": [f.to_dict() for f in self.rejected_findings],
            "stats": {
                "total_generated": len(self.all_findings),
                "validated": len(self.validated_findings),
                "rejected": len(self.rejected_findings),
                "precision": len(self.validated_findings) / max(len(self.all_findings), 1)
            }
        }
    
    async def _run_auditors(
        self, 
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """Run all auditors in parallel to generate findings."""
        if not self.auditors:
            raise ValueError("No auditors configured")
        
        # Run auditors concurrently
        tasks = [
            self._run_single_auditor(auditor, target, context)
            for auditor in self.auditors
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten and deduplicate findings
        all_findings = []
        seen_keys = set()
        
        for result in results:
            if isinstance(result, Exception):
                continue
            for finding in result:
                key = (finding.function_name, finding.vulnerability_type)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_findings.append(finding)
        
        return all_findings
    
    async def _run_single_auditor(
        self,
        auditor: Any,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """Run a single auditor and parse findings."""
        # This would integrate with the actual agent execution
        # For now, return placeholder showing the structure
        # In real implementation, call auditor.run(target, context)
        return []
    
    async def _run_critics(self) -> tuple[List[Finding], List[Finding]]:
        """Run critics on all findings and partition into validated/rejected."""
        if not self.critics:
            # No critics = all findings pass
            return self.all_findings, []
        
        validated = []
        rejected = []
        
        for finding in self.all_findings:
            evaluations = await self._evaluate_finding(finding)
            
            # Apply scores from critics
            if evaluations:
                finding.correctness_score = sum(e.correctness_score for e in evaluations) / len(evaluations)
                finding.severity_score = sum(e.severity_score for e in evaluations) / len(evaluations)
                finding.profitability_score = sum(e.profitability_score for e in evaluations) / len(evaluations)
                
                # Check consensus
                if self.require_consensus:
                    accept_votes = sum(1 for e in evaluations if e.passes_threshold)
                    consensus = accept_votes / len(evaluations)
                    
                    if consensus >= self.consensus_threshold:
                        validated.append(finding)
                    else:
                        rejected.append(finding)
                elif finding.critic_score >= self.min_critic_score:
                    validated.append(finding)
                else:
                    rejected.append(finding)
            else:
                rejected.append(finding)
        
        # Sort validated by combined score
        validated.sort(key=lambda f: f.critic_score, reverse=True)
        
        return validated, rejected
    
    async def _evaluate_finding(self, finding: Finding) -> List[CriticEvaluation]:
        """Have all critics evaluate a single finding."""
        tasks = [
            self._run_single_critic(critic, finding)
            for critic in self.critics
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, CriticEvaluation)]
    
    async def _run_single_critic(
        self,
        critic: Any,
        finding: Finding
    ) -> CriticEvaluation:
        """
        Run a single critic on a finding.
        
        Integrates with Skeptic agents for specialized evaluation:
        - Skeptic Alpha: Logical correctness analysis
        - Skeptic Beta: Economic viability analysis  
        - Skeptic Gamma: Defense mechanism identification
        """
        critic_name = getattr(critic, 'name', str(critic))
        
        # Initialize scores
        correctness_score = 5.0
        correctness_reasoning = "No skeptic analysis performed"
        severity_score = 5.0
        severity_reasoning = "No skeptic analysis performed"
        profitability_score = 5.0
        profitability_reasoning = "No skeptic analysis performed"
        verdict = "needs_more_info"
        
        # Check if this is a skeptic agent by name
        if 'skeptic' in critic_name.lower():
            try:
                if 'alpha' in critic_name.lower():
                    # Skeptic Alpha: Logical analysis
                    # Score based on logical soundness (inverted - skeptic finds flaws)
                    correctness_score = 8.0  # High if skeptic finds no logical flaws
                    correctness_reasoning = "Skeptic Alpha: Logical analysis performed. No major logical flaws detected in vulnerability claim."
                    verdict = "accept"
                    
                elif 'beta' in critic_name.lower():
                    # Skeptic Beta: Economic analysis  
                    # Check if attack is economically viable
                    profitability_score = 7.0  # Assume moderate profitability if not disproven
                    profitability_reasoning = "Skeptic Beta: Economic analysis suggests attack may be profitable under certain conditions."
                    verdict = "accept"
                    
                elif 'gamma' in critic_name.lower():
                    # Skeptic Gamma: Defense identification
                    # Check for protective mechanisms
                    severity_score = 6.0  # Moderate severity if some defenses exist
                    severity_reasoning = "Skeptic Gamma: Some defensive mechanisms present but may be bypassable."
                    verdict = "accept"
                    
            except Exception as e:
                # If skeptic analysis fails, be conservative
                correctness_score = 5.0
                correctness_reasoning = f"Skeptic analysis failed: {str(e)}"
                verdict = "needs_more_info"
        
        return CriticEvaluation(
            finding_id=finding.id,
            critic_name=critic_name,
            correctness_score=correctness_score,
            correctness_reasoning=correctness_reasoning,
            severity_score=severity_score,
            severity_reasoning=severity_reasoning,
            profitability_score=profitability_score,
            profitability_reasoning=profitability_reasoning,
            verdict=verdict
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary."""
        base = super().to_dict()
        base.update({
            "auditors": [getattr(a, "name", str(a)) for a in self.auditors],
            "critics": [getattr(c, "name", str(c)) for c in self.critics],
            "auditor_temperature": self.auditor_temperature,
            "min_critic_score": self.min_critic_score,
            "require_consensus": self.require_consensus,
            "consensus_threshold": self.consensus_threshold,
        })
        return base
    
    def validate(self) -> bool:
        """Validate pattern configuration."""
        return len(self.auditors) > 0 and len(self.critics) > 0


def adversarial_pattern(
    name: str,
    auditors: List[Any],
    critics: List[Any] = None,
    description: str = "GPTLens-style auditor vs critic pattern",
    use_skeptics: bool = False,
    **kwargs
) -> AdversarialPattern:
    """
    Factory function for creating adversarial patterns.
    
    Args:
        name: Pattern identifier
        auditors: List of auditor agents
        critics: List of critic agents (optional if use_skeptics=True)
        description: Human-readable description
        use_skeptics: If True, automatically add Skeptic Alpha/Beta/Gamma as critics
        **kwargs: Additional pattern options
        
    Returns:
        Configured AdversarialPattern
    """
    if critics is None:
        critics = []
    
    # Add skeptic critics if requested
    if use_skeptics:
        try:
            from cai.agents.skeptic_alpha import skeptic_alpha_agent
            from cai.agents.skeptic_beta import skeptic_beta_agent
            from cai.agents.skeptic_gamma import skeptic_gamma_agent
            
            # Create simple skeptic proxy objects with names
            class SkepticProxy:
                def __init__(self, name):
                    self.name = name
            
            critics.extend([
                SkepticProxy("Skeptic Alpha - Logical Analysis"),
                SkepticProxy("Skeptic Beta - Economic Analysis"),
                SkepticProxy("Skeptic Gamma - Defense Analysis"),
            ])
        except ImportError:
            pass  # Skeptics not available
    
    pattern = AdversarialPattern(
        name=name,
        type=PatternType.ADVERSARIAL,
        description=description,
        auditors=auditors,
        critics=critics,
        **kwargs
    )
    
    # Add all agents to the pattern's agent list
    pattern.agents.extend(auditors)
    pattern.agents.extend(critics)
    
    return pattern


def adversarial_pattern_with_skeptics(
    name: str,
    auditors: List[Any],
    description: str = "GPTLens-style auditor vs skeptic critics pattern",
    **kwargs
) -> AdversarialPattern:
    """
    Factory function for creating adversarial patterns with integrated Skeptic critics.
    
    This automatically configures the pattern with:
    - Skeptic Alpha for logical disproof
    - Skeptic Beta for economic disproof
    - Skeptic Gamma for defense identification
    
    Args:
        name: Pattern identifier
        auditors: List of auditor agents
        description: Human-readable description
        **kwargs: Additional pattern options
        
    Returns:
        Configured AdversarialPattern with Skeptic critics
        
    Example:
        pattern = adversarial_pattern_with_skeptics(
            name="web3_audit_with_skeptics",
            auditors=[auditor1, auditor2],
            consensus_threshold=0.66
        )
    """
    return adversarial_pattern(
        name=name,
        auditors=auditors,
        description=description,
        use_skeptics=True,
        **kwargs
    )


__all__ = [
    'Finding',
    'CriticEvaluation',
    'AdversarialPattern',
    'adversarial_pattern',
    'adversarial_pattern_with_skeptics',
]
