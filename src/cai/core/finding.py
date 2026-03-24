from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# Gate result for multi-gate verification pipeline (improvement_plan.md)
GateResult = Literal["passed", "failed", "dropped"]
ExploitabilityVerdict = Literal[
    "EXPLOITABLE – BOUNTY ELIGIBLE",
    "NOT EXPLOITABLE – ALREADY MITIGATED",
    "THEORETICAL / DESIGN RISK ONLY",
    "INVALID – NO REAL ATTACK PATH",
]

SEVERITY_RANK: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "optimization": 0,
}


@dataclass
class GateState:
    """Per-gate state for multi-gate verification. None = not yet evaluated."""

    tool_evidence: Optional[GateResult] = None
    pattern_fp: Optional[GateResult] = None
    judge: Optional[GateResult] = None
    disproof: Optional[GateResult] = None
    economic: Optional[GateResult] = None
    poc: Optional[GateResult] = None
    invariant: Optional[GateResult] = None


@dataclass
class ProofOfExploit:
    """Artifact linking a finding to a runnable PoC and impact assertion."""

    test_file: str
    impact_assertion: Optional[str] = None


@dataclass
class Finding:
    id: str
    vulnerability_type: str
    severity: str
    contract: str
    function_name: str
    location: str

    call_trace: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    taint_path: List[str] = field(default_factory=list)

    cross_contract: bool = False
    external_call_depth: int = 0
    privilege_required: bool = False

    exploit_path: Optional[List[str]] = None
    economic_profitability: Optional[float] = None
    gas_cost_estimate: Optional[float] = None

    fork_verified: bool = False
    invariant_broken: bool = False

    consensus_score: float = 0.0
    rejected_reason: Optional[str] = None
    rejection_reason_code: Optional[str] = None
    exploitability_verdict: Optional[ExploitabilityVerdict] = None
    description: Optional[str] = None
    attack_path_summary: Optional[str] = None
    preconditions_summary: Optional[str] = None
    affected_asset: Optional[str] = None
    permissionless: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    exploit_chain_id: Optional[str] = None
    engagement_snapshot: Optional[Dict[str, Any]] = None

    # Multi-gate verification (improvement_plan.md Phase 1)
    gate_state: GateState = field(default_factory=GateState)
    proof_of_exploit: Optional[ProofOfExploit] = None

    def attach_engagement_snapshot(self, snapshot: Dict[str, Any], chain_id: Optional[str] = None) -> None:
        self.engagement_snapshot = snapshot
        if chain_id:
            self.exploit_chain_id = chain_id
        self.metadata["engagement_snapshot_attached"] = True

    def passed_all_applicable_gates(self) -> bool:
        """True if no evaluated gate is failed/dropped. If no gates set, returns True (no filtering)."""
        g = self.gate_state
        for result in (
            g.tool_evidence,
            g.pattern_fp,
            g.judge,
            g.disproof,
            g.economic,
            g.poc,
            g.invariant,
        ):
            if result in ("failed", "dropped"):
                return False
        return True

    def is_critical(self) -> bool:
        return (
            self.fork_verified
            and self.invariant_broken
            and self.economic_profitability is not None
            and self.economic_profitability > 0
            and self.consensus_score >= 0.85
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict including all fields."""
        g = self.gate_state
        poc = self.proof_of_exploit
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "contract": self.contract,
            "function_name": self.function_name,
            "location": self.location,
            "description": self.description,
            "call_trace": self.call_trace,
            "state_variables": self.state_variables,
            "taint_path": self.taint_path,
            "cross_contract": self.cross_contract,
            "external_call_depth": self.external_call_depth,
            "privilege_required": self.privilege_required,
            "exploit_path": self.exploit_path,
            "economic_profitability": self.economic_profitability,
            "gas_cost_estimate": self.gas_cost_estimate,
            "fork_verified": self.fork_verified,
            "invariant_broken": self.invariant_broken,
            "consensus_score": self.consensus_score,
            "rejected_reason": self.rejected_reason,
            "rejection_reason_code": self.rejection_reason_code,
            "exploitability_verdict": self.exploitability_verdict,
            "attack_path_summary": self.attack_path_summary,
            "preconditions_summary": self.preconditions_summary,
            "affected_asset": self.affected_asset,
            "permissionless": self.permissionless,
            "metadata": self.metadata,
            "exploit_chain_id": self.exploit_chain_id,
            "engagement_snapshot": self.engagement_snapshot,
            "gate_state": {
                "tool_evidence": g.tool_evidence,
                "pattern_fp": g.pattern_fp,
                "judge": g.judge,
                "disproof": g.disproof,
                "economic": g.economic,
                "poc": g.poc,
                "invariant": g.invariant,
            },
            "proof_of_exploit": (
                {"test_file": poc.test_file, "impact_assertion": poc.impact_assertion}
                if poc is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        """Reconstruct a Finding from a dict produced by to_dict()."""
        gate_raw = d.get("gate_state") or {}
        gate = GateState(
            tool_evidence=gate_raw.get("tool_evidence"),
            pattern_fp=gate_raw.get("pattern_fp"),
            judge=gate_raw.get("judge"),
            disproof=gate_raw.get("disproof"),
            economic=gate_raw.get("economic"),
            poc=gate_raw.get("poc"),
            invariant=gate_raw.get("invariant"),
        )
        poc_raw = d.get("proof_of_exploit")
        poc = (
            ProofOfExploit(
                test_file=poc_raw["test_file"],
                impact_assertion=poc_raw.get("impact_assertion"),
            )
            if poc_raw
            else None
        )
        f = cls(
            id=d["id"],
            vulnerability_type=d["vulnerability_type"],
            severity=d["severity"],
            contract=d["contract"],
            function_name=d["function_name"],
            location=d["location"],
            description=d.get("description"),
            call_trace=d.get("call_trace") or [],
            state_variables=d.get("state_variables") or [],
            taint_path=d.get("taint_path") or [],
            cross_contract=bool(d.get("cross_contract", False)),
            external_call_depth=int(d.get("external_call_depth", 0)),
            privilege_required=bool(d.get("privilege_required", False)),
            exploit_path=d.get("exploit_path"),
            economic_profitability=d.get("economic_profitability"),
            gas_cost_estimate=d.get("gas_cost_estimate"),
            fork_verified=bool(d.get("fork_verified", False)),
            invariant_broken=bool(d.get("invariant_broken", False)),
            consensus_score=float(d.get("consensus_score", 0.0)),
            rejected_reason=d.get("rejected_reason"),
            rejection_reason_code=d.get("rejection_reason_code"),
            exploitability_verdict=d.get("exploitability_verdict"),
            attack_path_summary=d.get("attack_path_summary"),
            preconditions_summary=d.get("preconditions_summary"),
            affected_asset=d.get("affected_asset"),
            permissionless=d.get("permissionless"),
            metadata=d.get("metadata") or {},
            exploit_chain_id=d.get("exploit_chain_id"),
            engagement_snapshot=d.get("engagement_snapshot"),
            gate_state=gate,
            proof_of_exploit=poc,
        )
        return f
