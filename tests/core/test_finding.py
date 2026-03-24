"""Tests for cai.core.finding: Finding, GateState, ProofOfExploit, passed_all_applicable_gates."""

import pytest

from cai.core.finding import Finding, GateState, ProofOfExploit


def _minimal_finding(**kwargs) -> Finding:
    return Finding(
        id="test-1",
        vulnerability_type="reentrancy",
        severity="high",
        contract="Vault",
        function_name="withdraw",
        location="Vault.sol:42",
        **kwargs,
    )


class TestGateState:
    def test_default_all_none(self) -> None:
        g = GateState()
        assert g.tool_evidence is None
        assert g.judge is None
        assert g.poc is None

    def test_can_set_results(self) -> None:
        g = GateState(tool_evidence="passed", judge="failed")
        assert g.tool_evidence == "passed"
        assert g.judge == "failed"


class TestProofOfExploit:
    def test_minimal(self) -> None:
        p = ProofOfExploit(test_file="/path/to/test.t.sol")
        assert p.test_file == "/path/to/test.t.sol"
        assert p.impact_assertion is None

    def test_with_assertion(self) -> None:
        p = ProofOfExploit(
            test_file="/path/to/test.t.sol",
            impact_assertion="assertEq(victim.balance, 0)",
        )
        assert p.impact_assertion == "assertEq(victim.balance, 0)"


class TestFindingGateState:
    def test_default_gate_state_is_empty(self) -> None:
        f = _minimal_finding()
        assert f.gate_state is not None
        assert f.gate_state.tool_evidence is None
        assert f.gate_state.judge is None

    def test_default_no_proof_of_exploit(self) -> None:
        f = _minimal_finding()
        assert f.proof_of_exploit is None
        assert f.exploitability_verdict is None
        assert f.rejection_reason_code is None
        assert f.metadata == {}

    def test_can_attach_proof_of_exploit(self) -> None:
        f = _minimal_finding()
        f.proof_of_exploit = ProofOfExploit("test.t.sol", "assertEq(x, 0)")
        assert f.proof_of_exploit.test_file == "test.t.sol"
        assert f.proof_of_exploit.impact_assertion == "assertEq(x, 0)"


class TestPassedAllApplicableGates:
    def test_no_gates_set_returns_true(self) -> None:
        """Backward compat: no gate filtering when no gates evaluated."""
        f = _minimal_finding()
        assert f.passed_all_applicable_gates() is True

    def test_any_failed_returns_false(self) -> None:
        f = _minimal_finding()
        f.gate_state.tool_evidence = "passed"
        f.gate_state.judge = "failed"
        assert f.passed_all_applicable_gates() is False

    def test_any_dropped_returns_false(self) -> None:
        f = _minimal_finding()
        f.gate_state.judge = "dropped"
        assert f.passed_all_applicable_gates() is False

    def test_all_passed_returns_true(self) -> None:
        f = _minimal_finding()
        f.gate_state.tool_evidence = "passed"
        f.gate_state.judge = "passed"
        f.gate_state.poc = "passed"
        assert f.passed_all_applicable_gates() is True

    def test_some_set_all_passed_returns_true(self) -> None:
        f = _minimal_finding()
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "passed"
        # others left None
        assert f.passed_all_applicable_gates() is True


class TestIsCriticalUnchanged:
    """Ensure existing is_critical() behavior is unchanged."""

    def test_unchanged_without_gate_state_usage(self) -> None:
        f = _minimal_finding(
            fork_verified=True,
            invariant_broken=True,
            economic_profitability=0.5,
            consensus_score=0.9,
        )
        assert f.is_critical() is True

    def test_unchanged_missing_conditions(self) -> None:
        f = _minimal_finding(fork_verified=True, invariant_broken=False)
        assert f.is_critical() is False


class TestPipelineScenarioGateState:
    """Simulate gate results as set by EliteWeb3Pipeline stages."""

    def test_full_pass_through_pipeline_passes_all_gates(self) -> None:
        """Finding that would survive discovery -> skeptic -> exploit -> formal."""
        f = _minimal_finding(
            fork_verified=True,
            invariant_broken=True,
            economic_profitability=0.5,
            consensus_score=0.9,
        )
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "passed"
        f.gate_state.poc = "passed"
        f.gate_state.invariant = "passed"
        assert f.passed_all_applicable_gates() is True

    def test_skeptic_dropped_fails_gates(self) -> None:
        """Finding dropped at skeptic (e.g. owner-only) should not pass."""
        f = _minimal_finding()
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "dropped"
        assert f.passed_all_applicable_gates() is False

    def test_poc_failed_fails_gates(self) -> None:
        """Finding that failed fork test should not pass."""
        f = _minimal_finding()
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "passed"
        f.gate_state.poc = "failed"
        assert f.passed_all_applicable_gates() is False

    def test_invariant_failed_does_not_pass_gates(self) -> None:
        """invariant=failed means the finding did not pass the invariant gate; verified_findings excludes it."""
        f = _minimal_finding(fork_verified=True, invariant_broken=False)
        f.gate_state.tool_evidence = "passed"
        f.gate_state.pattern_fp = "passed"
        f.gate_state.poc = "passed"
        f.gate_state.invariant = "failed"
        assert f.passed_all_applicable_gates() is False


class TestPipelineReportStructure:
    """Report output includes gate_state and verified_findings (Step 2)."""

    def test_generate_report_includes_gate_state_and_verified_findings(self) -> None:
        from cai.web3.pipeline import EliteWeb3Pipeline

        pipeline = EliteWeb3Pipeline()
        f_pass = _minimal_finding(
            fork_verified=True,
            invariant_broken=True,
            economic_profitability=0.5,
            consensus_score=0.9,
        )
        f_pass.gate_state.tool_evidence = "passed"
        f_pass.gate_state.pattern_fp = "passed"
        f_pass.gate_state.poc = "passed"
        f_pass.gate_state.invariant = "passed"
        f_fail_gate = Finding(
            id="fail-1",
            vulnerability_type="reentrancy",
            severity="high",
            contract="Vault",
            function_name="withdraw",
            location="Vault.sol:42",
            fork_verified=True,
        )
        f_fail_gate.gate_state.poc = "failed"
        findings = [f_pass, f_fail_gate]
        report = pipeline.generate_report(findings)
        assert "summary" in report
        assert "mode_contract" in report
        assert "quality_metrics" in report
        assert report["summary"]["verified_findings_count"] == 1
        assert "verified_findings" in report
        assert len(report["verified_findings"]) == 1
        assert report["verified_findings"][0]["id"] == f_pass.id
        assert "gate_state" in report["verified_findings"][0]
        assert report["verified_findings"][0]["gate_state"]["poc"] == "passed"
        assert report["verified_findings"][0]["exploitability_verdict"] == "EXPLOITABLE – BOUNTY ELIGIBLE"
        assert "gate_state" in report["findings"][0]
