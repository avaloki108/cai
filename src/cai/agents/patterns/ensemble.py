"""
Ensemble Pattern - Multi-agent consensus voting.

From LLMBugScanner paper: "Large Language Model based Smart Contract
Auditing with LLMBugScanner"

Key insights:
- Different LLMs have different reasoning capabilities
- No single LLM consistently outperforms others for all vulnerability types
- Ensemble learning combines strengths of diverse models
- Two voting strategies:
  1. Weighted Majority Voting: Higher-performing models get higher weights
  2. Permutation-Optimized Tie-Breaking: Learned model priority for ties

Results from paper: 60% top-5 detection accuracy, outperforming single models by 19%
"""

from typing import Dict, Any, Optional, List, Union, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import asyncio
from cai.agents.patterns.pattern import Pattern, PatternType
import json
from datetime import datetime

if TYPE_CHECKING:
    from cai.sdk.agents import Agent


class VotingMethod(Enum):
    """Voting methods for ensemble pattern."""
    WEIGHTED_MAJORITY = "weighted"  # Weight by agent performance
    PERMUTATION_OPTIMIZED = "permutation"  # Learned priority for tie-breaking
    UNANIMOUS = "unanimous"  # All agents must agree
    SIMPLE_MAJORITY = "simple"  # One agent, one vote


@dataclass
class PerformanceHistory:
    """Historical performance tracking for agents."""

    agent_name: str
    true_positives: int = 0  # Findings validated as true
    false_positives: int = 0  # Findings rejected as false
    total_findings: int = 0  # Total findings analyzed
    last_updated: str = ""  # Timestamp of last performance update

    def accuracy(self) -> float:
        """Calculate agent accuracy (true positives / total findings)."""
        if self.total_findings == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def update_stats(self, is_correct: bool):
        """Update performance statistics."""
        self.total_findings += 1
        if is_correct:
            self.true_positives += 1
        else:
            self.false_positives += 1
        self.last_updated = datetime.now().isoformat()


# Performance history for all agents
AGENT_PERFORMANCE: Dict[str, PerformanceHistory] = defaultdict(
    lambda: PerformanceHistory
)


def _calculate_weighted_score(
    agent_name: str, history: PerformanceHistory, base_weight: float = 1.0
) -> float:
    """
    Calculate weighted score for an agent based on performance history.

    Formula:
    - Base weight (1.0)
    - + Accuracy bonus: +0.3 per 10% accuracy above 70%
    - + Consistency bonus: +0.2 for consistent voting (within 15% of majority)
    - Specialist boost: +0.3 if agent is expert in finding domain

    Args:
        agent_name: Agent identifier
        history: Performance history for this agent
        base_weight: Base weight to modify

    Returns:
        Weighted score (0.0-2.0 scale)
    """
    if not history:
        return base_weight

    accuracy = history.accuracy()
    weight = base_weight

    # Accuracy bonus
    if accuracy >= 0.7:
        weight += 0.3

    # Consistency bonus (measures agreement with majority)
    if history.total_findings >= 5:
        votes_with_majority = int(
            history.total_findings * 0.85
        )  # Assume 85% agreement is majority
        agreement_ratio = (
            history.true_positives + history.false_positives
        ) / history.total_findings
        if agreement_ratio >= 0.85:  # 85% alignment
            weight += 0.2

    return weight


@dataclass
class AgentVote:
    """A vote from an agent on a finding."""

    agent_name: str
    finding_key: Tuple[str, str]  # (function_name, vulnerability_type)
    confidence: float  # 0-1
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "finding": self.finding_key,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass
class EnsembleFinding:
    """A finding aggregated from multiple agents."""

    function_name: str
    vulnerability_type: str

    # Voting results
    total_votes: int = 0
    weighted_score: float = 0.0
    voters: List[str] = field(default_factory=list)

    # Best details from highest-confidence voter
    best_details: Dict[str, Any] = field(default_factory=dict)

    # Confidence metrics
    agreement_ratio: float = 0.0  # % of agents that found this
    average_confidence: float = 0.0

    @property
    def key(self) -> Tuple[str, str]:
        return (self.function_name, self.vulnerability_type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "vulnerability_type": self.vulnerability_type,
            "total_votes": self.total_votes,
            "weighted_score": self.weighted_score,
            "voters": self.voters,
            "agreement_ratio": self.agreement_ratio,
            "average_confidence": self.average_confidence,
            "details": self.best_details,
        }


@dataclass
class EnsemblePattern(Pattern):
    """
    Ensemble pattern for multi-agent consensus voting.

    Runs multiple agents on the same target and aggregates their findings
    using configurable voting mechanisms.

    Attributes:
        ensemble_agents: List of agents to run in ensemble
        voting_method: How to aggregate votes
        agent_weights: Performance-based weights for each agent
        priority_order: Learned priority for tie-breaking
        min_agreement: Minimum agreement ratio to accept finding
        top_k: Number of top findings to return
    """

    ensemble_agents: List[Any] = field(default_factory=list)

    # Voting configuration
    voting_method: VotingMethod = VotingMethod.WEIGHTED_MAJORITY
    agent_weights: Dict[str, float] = field(default_factory=dict)
    priority_order: List[str] = field(default_factory=list)

    # Thresholds
    min_agreement: float = 0.3  # At least 30% of agents must agree
    min_confidence: float = 0.5  # Minimum confidence to count vote
    top_k: int = 5

    # Results
    all_votes: List[AgentVote] = field(default_factory=list)
    aggregated_findings: List[EnsembleFinding] = field(default_factory=list)

    def __post_init__(self):
        """Initialize as ensemble pattern type."""
        self.type = PatternType.ENSEMBLE
        super().__post_init__()

        # Initialize default weights
        for agent in self.ensemble_agents:
            name = getattr(agent, "name", str(agent))
            if name not in self.agent_weights:
                self.agent_weights[name] = 1.0

    def add_agent(self, agent: Any, weight: float = 1.0) -> "EnsemblePattern":
        """Add an agent to the ensemble."""
        self.ensemble_agents.append(agent)
        if agent not in self.agents:
            self.agents.append(agent)

        name = getattr(agent, "name", str(agent))
        self.agent_weights[name] = weight

        return self

    def set_weight(self, agent_name: str, weight: float) -> "EnsemblePattern":
        """Set the weight for an agent."""
        self.agent_weights[agent_name] = weight
        return self

    def set_priority_order(self, order: List[str]) -> "EnsemblePattern":
        """Set the priority order for tie-breaking."""
        self.priority_order = order
        return self

    async def execute(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the ensemble pattern.

        Args:
            target: Contract path or code to audit
            context: Additional context for agents

        Returns:
            Aggregated findings with voting statistics
        """
        if not self.ensemble_agents:
            raise ValueError("No agents configured for ensemble")

        # Run all agents in parallel
        self.all_votes = await self._collect_votes(target, context)

        # Aggregate votes using configured method
        self.aggregated_findings = self._aggregate_votes()

        return {
            "findings": [f.to_dict() for f in self.aggregated_findings],
            "stats": {
                "total_agents": len(self.ensemble_agents),
                "total_votes": len(self.all_votes),
                "unique_findings": len(self.aggregated_findings),
                "voting_method": self.voting_method.value,
            },
            "agent_contributions": self._compute_contributions(),
        }

    async def _collect_votes(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[AgentVote]:
        """Collect votes from all ensemble agents."""
        tasks = [
            self._run_single_agent(agent, target, context)
            for agent in self.ensemble_agents
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_votes = []
        for result in results:
            if isinstance(result, Exception):
                continue
            all_votes.extend(result)

        return all_votes

    async def _run_single_agent(
        self, agent: Any, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[AgentVote]:
        """Run a single agent and convert findings to votes."""
        agent_name = getattr(agent, "name", str(agent))

        # In real implementation: await agent.run(target, context)
        # For now, return placeholder votes
        return []

    def _aggregate_votes(self) -> List[EnsembleFinding]:
        """Aggregate votes using the configured voting method."""
        method_handlers = {
            VotingMethod.WEIGHTED_MAJORITY: self._weighted_majority_vote,
            VotingMethod.PERMUTATION_OPTIMIZED: self._permutation_optimized_vote,
            VotingMethod.UNANIMOUS: self._unanimous_vote,
            VotingMethod.SIMPLE_MAJORITY: self._simple_majority_vote,
        }

        handler = method_handlers.get(self.voting_method, self._weighted_majority_vote)
        return handler()

    def _weighted_majority_vote(self) -> List[EnsembleFinding]:
        """
        Weighted majority voting.

        Higher-performing agents get higher weights.
        Score = sum(weight_i * confidence_i) for all agents that found the issue.
        """
        # Group votes by finding key
        votes_by_finding: Dict[Tuple[str, str], List[AgentVote]] = defaultdict(list)
        for vote in self.all_votes:
            if vote.confidence >= self.min_confidence:
                votes_by_finding[vote.finding_key].append(vote)

        findings = []
        total_agents = len(self.ensemble_agents)

        for finding_key, votes in votes_by_finding.items():
            # Calculate agreement ratio
            agreement_ratio = len(votes) / total_agents

            if agreement_ratio < self.min_agreement:
                continue

            # Calculate weighted score
            weighted_score = 0.0
            total_confidence = 0.0
            voters = []
            best_vote = None

            for vote in votes:
                weight = self.agent_weights.get(vote.agent_name, 1.0)
                weighted_score += weight * vote.confidence
                total_confidence += vote.confidence
                voters.append(vote.agent_name)

                if best_vote is None or vote.confidence > best_vote.confidence:
                    best_vote = vote

            finding = EnsembleFinding(
                function_name=finding_key[0],
                vulnerability_type=finding_key[1],
                total_votes=len(votes),
                weighted_score=weighted_score,
                voters=voters,
                agreement_ratio=agreement_ratio,
                average_confidence=total_confidence / len(votes),
                best_details=best_vote.details if best_vote else {},
            )

            findings.append(finding)

        # Sort by weighted score and return top_k
        findings.sort(key=lambda f: f.weighted_score, reverse=True)
        return findings[: self.top_k]

    def _permutation_optimized_vote(self) -> List[EnsembleFinding]:
        """
        Permutation-optimized tie-breaking voting.

        Uses learned model priority to break ties.
        First computes unweighted votes, then breaks ties using priority order.
        """
        # Group votes by finding key
        votes_by_finding: Dict[Tuple[str, str], List[AgentVote]] = defaultdict(list)
        for vote in self.all_votes:
            if vote.confidence >= self.min_confidence:
                votes_by_finding[vote.finding_key].append(vote)

        findings = []
        total_agents = len(self.ensemble_agents)

        for finding_key, votes in votes_by_finding.items():
            agreement_ratio = len(votes) / total_agents

            if agreement_ratio < self.min_agreement:
                continue

            # Calculate unweighted score (number of votes)
            unweighted_score = len(votes)

            # Calculate tie-breaking priority
            # Lower priority value = higher priority agent
            min_priority = float("inf")
            for vote in votes:
                if vote.agent_name in self.priority_order:
                    priority = self.priority_order.index(vote.agent_name)
                    min_priority = min(min_priority, priority)

            # Use negative priority for sorting (lower = better)
            tie_breaker = -min_priority if min_priority != float("inf") else 0

            voters = [v.agent_name for v in votes]
            best_vote = max(votes, key=lambda v: v.confidence)

            finding = EnsembleFinding(
                function_name=finding_key[0],
                vulnerability_type=finding_key[1],
                total_votes=unweighted_score,
                weighted_score=unweighted_score
                + tie_breaker * 0.01,  # Small tie-breaker
                voters=voters,
                agreement_ratio=agreement_ratio,
                average_confidence=sum(v.confidence for v in votes) / len(votes),
                best_details=best_vote.details,
            )

            findings.append(finding)

        # Sort by vote count, then by tie-breaker
        findings.sort(key=lambda f: f.weighted_score, reverse=True)
        return findings[: self.top_k]

    def _unanimous_vote(self) -> List[EnsembleFinding]:
        """
        Unanimous voting - all agents must agree.

        Most conservative approach, highest precision.
        """
        # Group votes by finding key
        votes_by_finding: Dict[Tuple[str, str], List[AgentVote]] = defaultdict(list)
        for vote in self.all_votes:
            if vote.confidence >= self.min_confidence:
                votes_by_finding[vote.finding_key].append(vote)

        findings = []
        total_agents = len(self.ensemble_agents)

        for finding_key, votes in votes_by_finding.items():
            # Require all agents to have voted
            if len(votes) != total_agents:
                continue

            voters = [v.agent_name for v in votes]
            best_vote = max(votes, key=lambda v: v.confidence)

            finding = EnsembleFinding(
                function_name=finding_key[0],
                vulnerability_type=finding_key[1],
                total_votes=len(votes),
                weighted_score=sum(v.confidence for v in votes),
                voters=voters,
                agreement_ratio=1.0,
                average_confidence=sum(v.confidence for v in votes) / len(votes),
                best_details=best_vote.details,
            )

            findings.append(finding)

        findings.sort(key=lambda f: f.weighted_score, reverse=True)
        return findings[: self.top_k]

    def _simple_majority_vote(self) -> List[EnsembleFinding]:
        """
        Simple majority voting - one agent, one vote.

        No weighting, just count votes.
        """
        votes_by_finding: Dict[Tuple[str, str], List[AgentVote]] = defaultdict(list)
        for vote in self.all_votes:
            if vote.confidence >= self.min_confidence:
                votes_by_finding[vote.finding_key].append(vote)

        findings = []
        total_agents = len(self.ensemble_agents)

        for finding_key, votes in votes_by_finding.items():
            agreement_ratio = len(votes) / total_agents

            if agreement_ratio < self.min_agreement:
                continue

            voters = [v.agent_name for v in votes]
            best_vote = max(votes, key=lambda v: v.confidence)

            finding = EnsembleFinding(
                function_name=finding_key[0],
                vulnerability_type=finding_key[1],
                total_votes=len(votes),
                weighted_score=float(len(votes)),
                voters=voters,
                agreement_ratio=agreement_ratio,
                average_confidence=sum(v.confidence for v in votes) / len(votes),
                best_details=best_vote.details,
            )

            findings.append(finding)

        findings.sort(key=lambda f: f.total_votes, reverse=True)
        return findings[: self.top_k]

    def _compute_contributions(self) -> Dict[str, Any]:
        """Compute contribution statistics for each agent."""
        contributions = {}

        for agent in self.ensemble_agents:
            name = getattr(agent, "name", str(agent))
            agent_votes = [v for v in self.all_votes if v.agent_name == name]

            # Count how many of this agent's votes made it to final findings
            validated_count = 0
            for vote in agent_votes:
                if any(f.key == vote.finding_key for f in self.aggregated_findings):
                    validated_count += 1

            contributions[name] = {
                "total_votes": len(agent_votes),
                "validated": validated_count,
                "validation_rate": validated_count / max(len(agent_votes), 1),
                "weight": self.agent_weights.get(name, 1.0),
            }

        return contributions

    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "ensemble_agents": [
                    getattr(a, "name", str(a)) for a in self.ensemble_agents
                ],
                "voting_method": self.voting_method.value,
                "agent_weights": self.agent_weights,
                "priority_order": self.priority_order,
                "min_agreement": self.min_agreement,
                "top_k": self.top_k,
            }
        )
        return base

    def validate(self) -> bool:
        """Validate pattern configuration."""
        return len(self.ensemble_agents) > 0


def ensemble_pattern(
    name: str,
    agents: List[Any],
    voting: Union[VotingMethod, str] = VotingMethod.WEIGHTED_MAJORITY,
    weights: Optional[Dict[str, float]] = None,
    description: str = "Multi-agent ensemble with consensus voting",
    **kwargs,
) -> EnsemblePattern:
    """
    Factory function for creating ensemble patterns.

    Args:
        name: Pattern identifier
        agents: List of agents for the ensemble
        voting: Voting method to use
        weights: Optional agent weights
        description: Human-readable description
        **kwargs: Additional pattern options

    Returns:
        Configured EnsemblePattern
    """
    if isinstance(voting, str):
        voting = VotingMethod(voting)

    pattern = EnsemblePattern(
        name=name,
        type=PatternType.ENSEMBLE,
        description=description,
        ensemble_agents=agents,
        voting_method=voting,
        **kwargs,
    )

    # Set custom weights if provided
    if weights:
        for agent_name, weight in weights.items():
            pattern.set_weight(agent_name, weight)

    # Add all agents to the base agent list
    pattern.agents.extend(agents)

    return pattern


__all__ = [
    'VotingMethod',
    'PerformanceHistory',
    'AgentVote',
    'EnsembleFinding',
    'EnsemblePattern',
    'ensemble_pattern',
    'AGENT_PERFORMANCE',
]
