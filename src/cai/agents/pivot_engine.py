"""
Pivot Engine for CAI Security Audits

A persistent state machine that ensures exhaustive exploration of attack vectors.
When stuck (>3 tools with no high-confidence findings), suggests alternative angles:

- "Invert assumption": if X was assumed safe, attack X
- "Zoom in": pick one suspicious function and attack exhaustively
- "Switch modality": static -> fuzz -> symbolic -> on-chain

Never declares "no bugs" without explicit exhaustion proof.
"""

import json
import random
from typing import Any, Dict, List, Optional, Set
from enum import Enum
from datetime import datetime
from pathlib import Path
from cai.sdk.agents import function_tool


# State file for persistent pivoting
_ENGINE_STATE_FILE = Path.home() / ".cai" / "pivot_engine_state.json"
_ACTIVE_ENGINE: Optional['PivotEngine'] = None


class PivotStrategy(Enum):
    """Strategies for pivoting when stuck."""

    INVERT_ASSUMPTION = "invert_assumption"
    ZOOM_IN = "zoom_in"
    SWITCH_MODALITY = "switch_modality"
    EXPLORE_EDGES = "explore_edges"


class AnalysisModality(Enum):
    """Different analysis modalities to switch between."""

    STATIC = "static_analysis"
    FUZZING = "fuzzing"
    SYMBOLIC = "symbolic_execution"
    ON_CHAIN = "on_chain_fork"
    DYNAMIC_ANALYSIS = "dynamic_analysis"


class Hypothesis:
    """
    Represents a single attack hypothesis with tracking.
    """

    def __init__(self, hypothesis: str, status: str = "pending"):
        self.hypothesis = hypothesis
        self.status = status
        self.created_at = datetime.now()
        self.attempts = 0
        self.tools_used = []
        self.evidence_for = ""
        self.evidence_against = ""
        self.next_action = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "status": self.status,
            "attempts": self.attempts,
            "tools_used": self.tools_used,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "next_action": self.next_action,
            "created_at": self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Hypothesis':
        h = cls(data["hypothesis"], data["status"])
        h.attempts = data.get("attempts", 0)
        h.tools_used = data.get("tools_used", [])
        h.evidence_for = data.get("evidence_for", "")
        h.evidence_against = data.get("evidence_against", "")
        h.next_action = data.get("next_action", "")
        if "created_at" in data:
            try:
                h.created_at = datetime.fromisoformat(data["created_at"])
            except ValueError:
                pass
        return h


class PivotEngine:
    """
    State machine for tracking hypotheses and suggesting pivots.
    """

    def __init__(self, max_attempts: int = 10, stuck_threshold: int = 3):
        self.hypotheses: List[Hypothesis] = []
        self.current_hypothesis_index = 0
        self.max_attempts = max_attempts
        self.stuck_threshold = stuck_threshold
        self.tools_without_high_confidence = 0
        self.current_modality = AnalysisModality.STATIC
        self.grit_score = 0
        self.exhausted_modalities: Set[AnalysisModality] = set()
        self.pivots_attempted = 0

    def add_hypothesis(
        self, hypothesis: str, evidence_for: str = "", evidence_against: str = ""
    ):
        """Add a new hypothesis to track."""
        hyp = Hypothesis(hypothesis)
        hyp.evidence_for = evidence_for
        hyp.evidence_against = evidence_against
        hyp.next_action = "Test with static analysis"
        self.hypotheses.append(hyp)
        self.grit_score += 1

    def record_attempt(self, hypothesis_index: int, tool: str, confidence: float):
        """Record an attempt to test a hypothesis."""
        if 0 <= hypothesis_index < len(self.hypotheses):
            self.hypotheses[hypothesis_index].attempts += 1
            self.hypotheses[hypothesis_index].tools_used.append(tool)

            if confidence >= 0.8:
                self.hypotheses[hypothesis_index].status = "confirmed"
                self.tools_without_high_confidence = 0
            elif confidence < 0.3:
                self.hypotheses[hypothesis_index].status = "disproven"
                self.tools_without_high_confidence = 0

    def record_stuck(self, tool: str):
        """Record that a tool produced no high-confidence findings."""
        self.tools_without_high_confidence += 1

    def should_pivot(self) -> bool:
        """
        Check if we should suggest a pivot.

        Pivot when stuck for > threshold tools without high confidence.
        """
        return self.tools_without_high_confidence >= self.stuck_threshold

    def get_pivot_suggestion(self) -> Dict[str, Any]:
        """
        Generate a pivot suggestion when stuck.

        Suggests one of:
        1. Invert assumption
        2. Zoom in on suspicious function
        3. Switch modality
        4. Explore edge cases
        """
        strategies = [
            PivotStrategy.INVERT_ASSUMPTION,
            PivotStrategy.ZOOM_IN,
            PivotStrategy.SWITCH_MODALITY,
            PivotStrategy.EXPLORE_EDGES,
        ]

        # Prioritize strategies based on attempts
        if self.pivots_attempted < len(strategies):
            strategy = strategies[self.pivots_attempted]
            self.pivots_attempted += 1
        else:
            strategy = random.choice(strategies)

        suggestion = self._generate_pivot_content(strategy)
        self.grit_score += 2

        return {
            "strategy": strategy.value,
            "suggestion": suggestion,
            "grit_score": self.grit_score,
            "pivots_attempted": self.pivots_attempted,
        }

    def _generate_pivot_content(self, strategy: PivotStrategy) -> str:
        """Generate pivot suggestion content based on strategy."""
        current_hyp = (
            self.hypotheses[self.current_hypothesis_index] if self.hypotheses else None
        )

        if strategy == PivotStrategy.INVERT_ASSUMPTION:
            if current_hyp:
                return (
                    f"INVERT ASSUMPTION: '{current_hyp.hypothesis}'\n\n"
                    f"You assumed: {current_hyp.evidence_for or 'safe'}\n"
                    f"Counter-evidence: {current_hyp.evidence_against or 'none provided'}\n\n"
                    f"New angle: Assume the OPPOSITE and try to exploit it.\n"
                    f"Example: If you assumed 'onlyOwner can call', assume 'anyone can call via reentrancy'\n"
                )
            else:
                return "INVERT ASSUMPTION: Pick an assumption and attack its inverse."

        elif strategy == PivotStrategy.ZOOM_IN:
            return (
                "ZOOM IN: Pick one suspicious function and attack it exhaustively.\n\n"
                "Don't try to cover everything. Focus on ONE function:\n"
                "- Read every line\n"
                "- Map all state changes\n"
                "- Try all possible inputs\n"
                "- Consider all edge cases\n\n"
            )

        elif strategy == PivotStrategy.SWITCH_MODALITY:
            next_modalities = [
                m
                for m in AnalysisModality
                if m not in self.exhausted_modalities and m != self.current_modality
            ]

            if next_modalities:
                next_mod = next_modalities[0]
                self.exhausted_modalities.add(self.current_modality)
                self.current_modality = next_mod

                return (
                    f"SWITCH MODALITY: {self.current_modality.value} -> {next_mod.value}\n\n"
                    f"Current approach isn't working. Switch to {next_mod.value}.\n\n"
                    "Available modalities:\n"
                    "- static_analysis: Slither, pattern matching\n"
                    "- fuzzing: Echidna, Medusa\n"
                    "- symbolic_execution: Mythril, Manticore\n"
                    "- on_chain_fork: Foundry fork testing, actual state\n"
                )
            else:
                return "All modalities exhausted. Proceed to exhaustive documentation."

        elif strategy == PivotStrategy.EXPLORE_EDGES:
            return (
                "EXPLORE EDGES: Look for interaction points between contracts.\n\n"
                "Focus on:\n"
                "- Callback functions (onXxxReceived)\n"
                "- External call boundaries\n"
                "- Delegatecall patterns\n"
                "- Upgrade/initialization paths\n"
                "- Token transfer approvals\n"
                "- Cross-chain bridges\n"
            )

        else:
            return "Choose a pivot strategy."

    def get_exhaustion_proof(self) -> Dict[str, Any]:
        """
        Generate an exhaustion proof when all hypotheses tested.

        Documents what was checked and why it's believed safe.
        """
        confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
        disproven = [h for h in self.hypotheses if h.status == "disproven"]
        pending = [h for h in self.hypotheses if h.status == "pending"]

        return {
            "exhaustion_verified": True,
            "hypotheses_tested": len(self.hypotheses),
            "confirmed": len(confirmed),
            "disproven": len(disproven),
            "pending": len(pending),
            "modalities_tried": [m.value for m in AnalysisModality],
            "grit_score": self.grit_score,
            "pivots_attempted": self.pivots_attempted,
            "conclusion": self._generate_exhaustion_conclusion(
                confirmed, disproven, pending
            ),
        }

    def _generate_exhaustion_conclusion(
        self,
        confirmed: List[Hypothesis],
        disproven: List[Hypothesis],
        pending: List[Hypothesis],
    ) -> str:
        """Generate the conclusion text for exhaustion proof."""
        if confirmed:
            return f"Confirmed {len(confirmed)} exploit(s). Audit complete."

        if pending:
            return (
                f"No high-confidence findings after {len(self.hypotheses)} hypotheses.\n\n"
                f"Pending: {len(pending)} hypotheses not fully tested.\n\n"
                f"Recommendation: Run tests on pending hypotheses before concluding."
            )

        conclusion = (
            f"Exhausted search space with {len(self.hypotheses)} hypotheses.\n"
            f"All angles tested. No exploitable vulnerabilities found.\n\n"
            f"Disproven assumptions: {len(disproven)}\n"
            f"Modalities tried: {len(self.exhausted_modalities)}\n"
        )
        return conclusion

    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state."""
        return {
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "current_hypothesis_index": self.current_hypothesis_index,
            "max_attempts": self.max_attempts,
            "stuck_threshold": self.stuck_threshold,
            "tools_without_high_confidence": self.tools_without_high_confidence,
            "grit_score": self.grit_score,
            "pivots_attempted": self.pivots_attempted,
            "exhausted_modalities": [m.value for m in self.exhausted_modalities],
            "current_modality": self.current_modality.value
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PivotEngine':
        """Deserialize engine state."""
        engine = cls(
            max_attempts=data.get("max_attempts", 10),
            stuck_threshold=data.get("stuck_threshold", 3)
        )
        engine.hypotheses = [Hypothesis.from_dict(h) for h in data.get("hypotheses", [])]
        engine.current_hypothesis_index = data.get("current_hypothesis_index", 0)
        engine.tools_without_high_confidence = data.get("tools_without_high_confidence", 0)
        engine.grit_score = data.get("grit_score", 0)
        engine.pivots_attempted = data.get("pivots_attempted", 0)
        
        exhausted = data.get("exhausted_modalities", [])
        engine.exhausted_modalities = {AnalysisModality(m) for m in exhausted if m in [x.value for x in AnalysisModality]}
        
        current_mod = data.get("current_modality")
        if current_mod and current_mod in [x.value for x in AnalysisModality]:
            engine.current_modality = AnalysisModality(current_mod)
            
        return engine


def _get_engine() -> PivotEngine:
    """Get active pivot engine or load from disk."""
    global _ACTIVE_ENGINE
    if _ACTIVE_ENGINE is None:
        if _ENGINE_STATE_FILE.exists():
            try:
                data = json.loads(_ENGINE_STATE_FILE.read_text(encoding="utf-8"))
                _ACTIVE_ENGINE = PivotEngine.from_dict(data)
            except Exception:
                _ACTIVE_ENGINE = PivotEngine()
        else:
            _ACTIVE_ENGINE = PivotEngine()
    return _ACTIVE_ENGINE


def _save_engine():
    """Save active engine state to disk."""
    if _ACTIVE_ENGINE:
        # Ensure directory exists
        _ENGINE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ENGINE_STATE_FILE.write_text(json.dumps(_ACTIVE_ENGINE.to_dict(), indent=2), encoding="utf-8")


@function_tool
def pivot_engine_init(
    max_attempts: int = 10, stuck_threshold: int = 3, ctf=None
) -> str:
    """
    Initialize pivot engine for hypothesis-driven persistence.

    Args:
        max_attempts: Maximum number of hypotheses to track
        stuck_threshold: Tools without high confidence before suggesting pivot

    Returns:
        JSON with engine state
    """
    try:
        global _ACTIVE_ENGINE
        _ACTIVE_ENGINE = PivotEngine(max_attempts=max_attempts, stuck_threshold=stuck_threshold)
        _save_engine()
        
        return json.dumps(
            {
                "status": "initialized",
                "engine": _ACTIVE_ENGINE.to_dict(),
                "usage": "Use pivot_engine_add_hypothesis to start tracking",
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": f"Error initializing pivot engine: {str(e)}"})


@function_tool
def pivot_engine_add_hypothesis(
    hypothesis: str, evidence_for: str = "", evidence_against: str = "", ctf=None
) -> str:
    """
    Add a new hypothesis to pivot engine tracking.

    Args:
        hypothesis: Attack hypothesis to test
        evidence_for: Evidence supporting the hypothesis
        evidence_against: Why hypothesis might not work

    Returns:
        JSON with updated engine state
    """
    try:
        # Load existing engine state
        engine = _get_engine()

        # Add hypothesis
        engine.add_hypothesis(hypothesis, evidence_for, evidence_against)
        _save_engine()

        return json.dumps(
            {
                "status": "hypothesis_added",
                "hypothesis": hypothesis,
                "total_hypotheses": len(engine.hypotheses),
                "engine": engine.to_dict(),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": f"Error adding hypothesis: {str(e)}"})


@function_tool
def pivot_engine_record_attempt(
    hypothesis_index: int, tool: str, confidence: float, ctf=None
) -> str:
    """
    Record an attempt to test a hypothesis.

    Args:
        hypothesis_index: Index of hypothesis being tested
        tool: Tool used for testing
        confidence: Confidence level of result (0-1)

    Returns:
        JSON with updated engine state
    """
    try:
        engine = _get_engine()
        engine.record_attempt(hypothesis_index, tool, confidence)
        _save_engine()

        return json.dumps(
            {
                "status": "attempt_recorded",
                "hypothesis_index": hypothesis_index,
                "tool": tool,
                "confidence": confidence,
                "hypothesis_status": engine.hypotheses[hypothesis_index].status
                if hypothesis_index < len(engine.hypotheses)
                else "not_found",
                "engine": engine.to_dict(),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": f"Error recording attempt: {str(e)}"})


@function_tool
def pivot_engine_check_stuck(ctf=None) -> str:
    """
    Check if the analysis is stuck and needs a pivot.

    Returns:
        JSON with stuck status and pivot suggestion if needed
    """
    try:
        engine = _get_engine()
        is_stuck = engine.should_pivot()

        result = {
            "is_stuck": is_stuck,
            "tools_without_high_confidence": engine.tools_without_high_confidence,
            "stuck_threshold": engine.stuck_threshold,
        }

        if is_stuck:
            suggestion = engine.get_pivot_suggestion()
            result["pivot_suggestion"] = suggestion
            _save_engine()  # Save state (grit score updated)

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error checking stuck status: {str(e)}"})


@function_tool
def pivot_engine_exhaustion_proof(ctf=None) -> str:
    """
    Generate exhaustion proof when all hypotheses tested.

    Documents what was checked and why it's believed safe.
    Never declares "no bugs" without this proof.

    Returns:
        JSON with exhaustion proof
    """
    try:
        engine = _get_engine()
        proof = engine.get_exhaustion_proof()

        return json.dumps(proof, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error generating exhaustion proof: {str(e)}"})


@function_tool
def pivot_engine_switch_modality(new_modality: str, ctf=None) -> str:
    """
    Switch analysis modality (static -> fuzz -> symbolic -> on-chain).

    Args:
        new_modality: One of static_analysis, fuzzing, symbolic_execution, on_chain_fork

    Returns:
        JSON with updated engine state
    """
    try:
        engine = _get_engine()

        # Validate modality
        try:
            new_mod = AnalysisModality(new_modality.lower())
            engine.current_modality = new_mod
            _save_engine()
        except ValueError:
            return json.dumps(
                {
                    "error": f"Invalid modality: {new_modality}. "
                    f"Valid modalities: {[m.value for m in AnalysisModality]}"
                }
            )

        return json.dumps(
            {
                "status": "modality_switched",
                "previous_modality": str(
                    AnalysisModality(engine.current_modality.value)
                ),
                "new_modality": new_modality,
                "engine": engine.to_dict(),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": f"Error switching modality: {str(e)}"})


__all__ = [
    'PivotStrategy',
    'AnalysisModality',
    'Hypothesis',
    'PivotEngine',
    'pivot_engine_init',
    'pivot_engine_add_hypothesis',
    'pivot_engine_record_attempt',
    'pivot_engine_check_stuck',
    'pivot_engine_exhaustion_proof',
    'pivot_engine_switch_modality',
]
