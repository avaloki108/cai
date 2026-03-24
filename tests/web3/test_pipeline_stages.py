"""
Unit tests for EliteWeb3Pipeline stage logic.

These tests exercise pure-logic stages without invoking Slither or Foundry,
so they run without any external tools installed.
"""

import asyncio
import pytest

from cai.core.finding import Finding, GateState
from cai.web3.pipeline import EliteWeb3Pipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(
    vuln_type: str = "reentrancy",
    contract: str = "Vault",
    function_name: str = "withdraw",
    severity: str = "high",
    external_call_depth: int = 1,
    state_variables: list | None = None,
    location: str = "Vault.sol:10",
    description: str = "",
    privilege_required: bool = False,
) -> Finding:
    f = Finding(
        id=f"{vuln_type}_{contract}_{function_name}",
        vulnerability_type=vuln_type,
        severity=severity,
        contract=contract,
        function_name=function_name,
        location=location,
        description=description,
    )
    f.external_call_depth = external_call_depth
    f.state_variables = state_variables if state_variables is not None else ["balance"]
    f.privilege_required = privilege_required
    return f


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Stage 2 — Risk Prioritization
# ---------------------------------------------------------------------------

class TestRiskPrioritization:
    def test_sorts_by_descending_score(self):
        pipeline = EliteWeb3Pipeline()
        pipeline.stage_metrics = {"risk_prioritization": {}}
        low = _f("info_only", external_call_depth=0, state_variables=[], privilege_required=True)
        high = _f("reentrancy", external_call_depth=3, state_variables=["a", "b"], privilege_required=False)
        result = _run(pipeline.risk_prioritization([low, high]))
        assert result[0].id == high.id

    def test_permissionless_bonus_applied(self):
        pipeline = EliteWeb3Pipeline()
        pipeline.stage_metrics = {"risk_prioritization": {}}
        permless = _f("reentrancy", privilege_required=False)
        priv = _f("reentrancy", function_name="adminWithdraw", privilege_required=True)
        result = _run(pipeline.risk_prioritization([priv, permless]))
        assert result[0].id == permless.id

    def test_score_assigned_to_all_findings(self):
        pipeline = EliteWeb3Pipeline()
        pipeline.stage_metrics = {"risk_prioritization": {}}
        findings = [_f("a", function_name=f"fn{i}") for i in range(5)]
        result = _run(pipeline.risk_prioritization(findings))
        for f in result:
            assert f.consensus_score >= 0.0


# ---------------------------------------------------------------------------
# Stage 3 — Skeptic
# ---------------------------------------------------------------------------

class TestSkepticStage:
    def _pipeline(self):
        p = EliteWeb3Pipeline()
        p.stage_metrics = {
            "skeptic": {"input": 0, "output": 0, "rejected": 0, "rejection_reasons": {}},
        }
        return p

    def test_rejects_onlyowner_in_location(self):
        p = self._pipeline()
        f = _f(location="Vault.sol:10 onlyOwner")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 0
        assert f.rejected_reason is not None
        assert f.rejection_reason_code == "already_mitigated"
        assert f.exploitability_verdict == "NOT EXPLOITABLE – ALREADY MITIGATED"
        assert f.gate_state.pattern_fp == "dropped"

    def test_rejects_privilege_in_description(self):
        p = self._pipeline()
        f = _f(description="This function uses onlyAdmin modifier to restrict access.")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 0
        assert f.rejection_reason_code == "already_mitigated"

    def test_rejects_initializer_pattern(self):
        p = self._pipeline()
        f = _f(description="Callable only via initializer function.")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 0

    def test_rejects_timelock_in_description(self):
        p = self._pipeline()
        f = _f(description="Requires timelock delay before execution.")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 0

    def test_rejects_no_state_no_calls(self):
        p = self._pipeline()
        f = _f(external_call_depth=0, state_variables=[], description="")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 0
        assert f.rejection_reason_code == "theoretical_only"
        assert f.exploitability_verdict == "THEORETICAL / DESIGN RISK ONLY"

    def test_passes_permissionless_state_mutating(self):
        p = self._pipeline()
        f = _f(external_call_depth=1, state_variables=["balance"], description="Public permissionless withdraw")
        result = _run(p.skeptic_stage([f]))
        assert len(result) == 1
        assert f.gate_state.pattern_fp == "passed"

    def test_consensus_score_bumped_for_survivor(self):
        p = self._pipeline()
        f = _f()
        f.consensus_score = 0.5
        _run(p.skeptic_stage([f]))
        assert f.consensus_score == pytest.approx(0.7)

    def test_metrics_tracked(self):
        p = self._pipeline()
        survivor = _f(function_name="deposit")
        rejected = _f(location="onlyOwner", function_name="adminFn")
        _run(p.skeptic_stage([survivor, rejected]))
        assert p.stage_metrics["skeptic"]["output"] == 1
        assert p.stage_metrics["skeptic"]["rejected"] == 1


# ---------------------------------------------------------------------------
# Stage 5 — Formal
# ---------------------------------------------------------------------------

class TestFormalStage:
    def _pipeline(self):
        p = EliteWeb3Pipeline()
        p.stage_metrics = {
            "formal": {"input": 0, "output": 0, "invariant_passed": 0, "invariant_failed": 0},
        }
        return p

    @pytest.mark.parametrize("vuln_type", ["reentrancy", "overflow", "precision_loss", "oracle-manipulation"])
    def test_known_types_pass_invariant(self, vuln_type):
        p = self._pipeline()
        f = _f(vuln_type=vuln_type)
        _run(p.formal_stage([f]))
        assert f.invariant_broken is True
        assert f.gate_state.invariant == "passed"
        assert p.stage_metrics["formal"]["invariant_passed"] == 1

    def test_unknown_type_fails_invariant(self):
        p = self._pipeline()
        f = _f(vuln_type="obscure-pattern", severity="high")
        _run(p.formal_stage([f]))
        assert f.invariant_broken is False
        assert f.gate_state.invariant == "failed"
        assert f.severity == "medium"
        assert p.stage_metrics["formal"]["invariant_failed"] == 1

    def test_unknown_type_gets_theoretical_verdict(self):
        p = self._pipeline()
        f = _f(vuln_type="random-check")
        f.exploitability_verdict = None
        _run(p.formal_stage([f]))
        assert f.exploitability_verdict == "THEORETICAL / DESIGN RISK ONLY"

    def test_existing_verdict_not_overwritten_by_formal(self):
        p = self._pipeline()
        f = _f(vuln_type="random-check")
        f.exploitability_verdict = "EXPLOITABLE – BOUNTY ELIGIBLE"
        _run(p.formal_stage([f]))
        assert f.exploitability_verdict == "EXPLOITABLE – BOUNTY ELIGIBLE"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplicate:
    def _pipeline(self):
        p = EliteWeb3Pipeline()
        p.stage_metrics = {"discovery": {"deduplicated": 0}}
        return p

    def test_removes_exact_duplicate(self):
        p = self._pipeline()
        f1 = _f("reentrancy", "Vault", "withdraw", "high")
        f2 = _f("reentrancy", "Vault", "withdraw", "high")
        result = p._deduplicate([f1, f2])
        assert len(result) == 1

    def test_keeps_highest_severity(self):
        p = self._pipeline()
        low = _f("reentrancy", "Vault", "withdraw", "low")
        high = _f("reentrancy", "Vault", "withdraw", "high")
        result = p._deduplicate([low, high])
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_different_contracts_kept_separate(self):
        p = self._pipeline()
        f1 = _f("reentrancy", "Vault", "withdraw")
        f2 = _f("reentrancy", "Treasury", "withdraw")
        result = p._deduplicate([f1, f2])
        assert len(result) == 2

    def test_different_functions_kept_separate(self):
        p = self._pipeline()
        f1 = _f("reentrancy", "Vault", "withdraw")
        f2 = _f("reentrancy", "Vault", "flashLoan")
        result = p._deduplicate([f1, f2])
        assert len(result) == 2

    def test_metric_tracks_count(self):
        p = self._pipeline()
        findings = [
            _f("reentrancy", "Vault", "withdraw", "high"),
            _f("reentrancy", "Vault", "withdraw", "low"),
            _f("reentrancy", "Vault", "withdraw", "medium"),
        ]
        result = p._deduplicate(findings)
        assert len(result) == 1
        assert p.stage_metrics["discovery"]["deduplicated"] == 2


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

class TestSeverityFilter:
    def _pipeline(self):
        p = EliteWeb3Pipeline()
        p.stage_metrics = {"discovery": {"severity_filtered": 0, "output": 0}}
        return p

    @pytest.mark.parametrize("sev", ["Informational", "informational", "INFORMATIONAL"])
    def test_drops_informational(self, sev):
        p = self._pipeline()
        f = _f(severity=sev)
        result = p._filter_low_severity([f])
        assert len(result) == 0
        assert p.stage_metrics["discovery"]["severity_filtered"] == 1

    @pytest.mark.parametrize("sev", ["Optimization", "optimization"])
    def test_drops_optimization(self, sev):
        p = self._pipeline()
        f = _f(severity=sev)
        result = p._filter_low_severity([f])
        assert len(result) == 0

    @pytest.mark.parametrize("sev", ["high", "medium", "low", "critical"])
    def test_keeps_actionable_severities(self, sev):
        p = self._pipeline()
        f = _f(severity=sev)
        result = p._filter_low_severity([f])
        assert len(result) == 1

    def test_mixed_batch(self):
        p = self._pipeline()
        findings = [
            _f(severity="high"),
            _f(severity="Informational", function_name="fn2"),
            _f(severity="medium", function_name="fn3"),
            _f(severity="Optimization", function_name="fn4"),
        ]
        result = p._filter_low_severity(findings)
        assert len(result) == 2
        assert p.stage_metrics["discovery"]["severity_filtered"] == 2


# ---------------------------------------------------------------------------
# Finding.to_dict / from_dict round-trip
# ---------------------------------------------------------------------------

class TestFindingSerDe:
    def test_round_trip_minimal(self):
        f = _f()
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.id == f.id
        assert f2.vulnerability_type == f.vulnerability_type
        assert f2.severity == f.severity

    def test_round_trip_with_gate_state(self):
        f = _f(vuln_type="reentrancy")
        f.gate_state.tool_evidence = "passed"
        f.gate_state.poc = "failed"
        f.exploitability_verdict = "INVALID – NO REAL ATTACK PATH"
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.gate_state.tool_evidence == "passed"
        assert f2.gate_state.poc == "failed"
        assert f2.exploitability_verdict == "INVALID – NO REAL ATTACK PATH"

    def test_round_trip_with_description(self):
        f = _f(description="Reentrancy in _withdraw allows double-spend")
        d = f.to_dict()
        assert d["description"] == f.description
        f2 = Finding.from_dict(d)
        assert f2.description == f.description

    def test_to_dict_includes_severity_and_description(self):
        f = _f(severity="critical", description="Critical bug")
        d = f.to_dict()
        assert "severity" in d
        assert "description" in d
        assert d["severity"] == "critical"
        assert d["description"] == "Critical bug"


# ---------------------------------------------------------------------------
# Report: severity and description present
# ---------------------------------------------------------------------------

class TestReportFields:
    def test_report_includes_severity_and_description(self):
        pipeline = EliteWeb3Pipeline()
        pipeline.stage_metrics = {
            "exploit": {"verified": 1, "input": 1},
        }
        f = _f(vuln_type="reentrancy", severity="high", description="Classic CEI violation")
        f.fork_verified = True
        f.invariant_broken = True
        f.economic_profitability = 0.5
        f.consensus_score = 0.9
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "passed"
        f.gate_state.poc = "passed"
        f.gate_state.invariant = "passed"
        report = pipeline.generate_report([f])
        finding_dicts = report["findings"] + report["verified_findings"]
        assert len(finding_dicts) > 0
        for fd in finding_dicts:
            assert "severity" in fd
            assert "description" in fd
