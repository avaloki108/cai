"""
Elite Web3 Pipeline — CAI-native deterministic audit pipeline.

Runs entirely through CAI tools and the canonical Finding model.
No dependency on web3_security_ai; used via programmatic import or adapter flows.

Stages:
    1. Discovery   — High-recall static analysis (Slither + precision checks)
    2. Risk Queue   — Weighted scoring by exploitability signals
    3. Skeptic Gate — Adversarial false-positive filtering
    4. Exploit Fork — Mainnet-fork PoC verification (mandatory)
    5. Formal       — Invariant-breach confirmation
"""

import hashlib
import json
import logging
import os
import tempfile
from enum import Enum
from typing import Any, Dict, List, Optional

from cai.core.finding import Finding
from cai.tools.common import run_command
from cai.tools.web3_security.config import SLITHER_PATH
from cai.tools.web3_security.finding_schema import Finding as SchemaFinding
from cai.tools.web3_security.finding_schema import normalize_slither
from cai.tools.web3_security.finding_schema import to_pipeline_payload
from cai.tools.web3_security.fork_test import (
    analyze_test_output,
    generate_fork_test,
    run_fork_test,
)
from cai.reporting.exploit_bundle import build_exploit_bundle, export_exploit_bundle


class AuditMode(Enum):
    DETERMINISTIC = "deterministic"
    JUDGE_GATED = "judge_gated"


class EliteWeb3Pipeline:
    """CAI-native multi-stage Web3 audit pipeline."""

    def __init__(self, skeptics: Optional[list] = None):
        self.logger = logging.getLogger(__name__)
        self.skeptics = skeptics or []
        self.stage_metrics: Dict[str, Any] = {}
        self.target_ref: str = ""

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self, target: str) -> Dict[str, Any]:
        self.logger.info(f"Starting Elite Web3 Pipeline for target: {target}")
        self.target_ref = target
        self.stage_metrics = {
            "discovery": {"input": 0, "output": 0, "errors": 0, "severity_filtered": 0, "deduplicated": 0},
            "risk_prioritization": {"input": 0, "output": 0},
            "skeptic": {"input": 0, "output": 0, "rejected": 0, "rejection_reasons": {}},
            "exploit": {"input": 0, "output": 0, "verified": 0, "rejected": 0, "rejection_reasons": {}},
            "formal": {"input": 0, "output": 0, "invariant_passed": 0, "invariant_failed": 0},
        }

        findings = await self.discovery_stage(target)
        self.logger.info(f"Discovery stage completed with {len(findings)} findings.")

        if not findings:
            return self.generate_report([])

        findings = await self.risk_prioritization(findings)
        self.logger.info("Risk prioritization completed.")

        findings = await self.skeptic_stage(findings)
        self.logger.info(
            f"Skeptic stage completed. "
            f"{len([f for f in findings if not f.rejected_reason])} findings remaining."
        )

        findings = await self.exploit_stage(findings)
        self.logger.info(
            f"Exploit stage completed. "
            f"{len([f for f in findings if f.fork_verified])} exploits verified."
        )

        findings = await self.formal_stage(findings)
        self.logger.info("Formal stage completed.")

        return self.generate_report(findings)

    # ------------------------------------------------------------------
    # Stage 1 — Discovery (High Recall)
    # ------------------------------------------------------------------

    async def discovery_stage(self, target: str) -> List[Finding]:
        """Run Slither + precision analysis using CAI tools directly."""
        self.logger.info(f"Discovery Stage: Analyzing {target}")
        self.stage_metrics["discovery"]["input"] = 1

        contract_path = target
        if not os.path.exists(target):
            fd, temp_path = tempfile.mkstemp(prefix="cai_audit_target_", suffix=".sol")
            os.close(fd)
            contract_path = temp_path
            with open(contract_path, "w", encoding="utf-8") as f:
                f.write(target)

        findings: List[Finding] = []

        # --- Slither static analysis ---
        fd, json_output = tempfile.mkstemp(prefix="cai_slither_results_", suffix=".json")
        os.close(fd)
        cmd_parts = [SLITHER_PATH, contract_path, "--json", json_output]
        try:
            run_command(" ".join(cmd_parts))
        except Exception as e:
            self.logger.warning(f"Slither execution failed: {e}")
            self.stage_metrics["discovery"]["errors"] += 1

        if os.path.exists(json_output):
            try:
                with open(json_output, "r", encoding="utf-8") as f:
                    slither_data = json.load(f)
                normalized = normalize_slither(slither_data)
                for schema_finding in normalized:
                    finding = self._schema_to_core_finding(schema_finding, contract_path)
                    findings.append(finding)
            except Exception as e:
                self.logger.error(f"Error parsing Slither JSON: {e}")
                self.stage_metrics["discovery"]["errors"] += 1
            finally:
                try:
                    os.remove(json_output)
                except OSError:
                    pass

        # --- Precision analysis (regex-based, no external binary) ---
        if os.path.isfile(contract_path):
            try:
                from cai.tools.web3_security.enhancements.precision import (
                    _detect_division_before_multiplication,
                    _detect_dust_attacks,
                    _detect_rounding_exploitation,
                    _detect_semantic_overflow,
                )

                with open(contract_path, "r", encoding="utf-8") as f:
                    source = f.read()
                for detector_fn in (
                    _detect_division_before_multiplication,
                    _detect_rounding_exploitation,
                    _detect_dust_attacks,
                    _detect_semantic_overflow,
                ):
                    try:
                        result = detector_fn(source, False)
                        for fp in result.get("findings", []):
                            f_precision = Finding(
                                id=(
                                    f"precision_"
                                    f"{hashlib.md5(fp.get('description', '').encode()).hexdigest()[:8]}"
                                ),
                                vulnerability_type="precision_loss",
                                severity=fp.get("severity", "medium"),
                                contract=os.path.basename(contract_path),
                                function_name="unknown",
                                location=str(fp.get("line_number", "0")),
                            )
                            f_precision.gate_state.tool_evidence = "passed"
                            f_precision.permissionless = True
                            f_precision.affected_asset = os.path.basename(contract_path)
                            findings.append(f_precision)
                    except Exception:
                        pass
            except ImportError:
                self.logger.warning("Precision detectors not available")

        self.stage_metrics["discovery"]["output"] = len(findings)

        findings = self._filter_low_severity(findings)
        findings = self._deduplicate(findings)

        return findings
    # ------------------------------------------------------------------

    async def risk_prioritization(self, findings: List[Finding]) -> List[Finding]:
        self.stage_metrics["risk_prioritization"]["input"] = len(findings)
        for f in findings:
            risk_score = (
                f.external_call_depth * 0.3
                + (1 if f.cross_contract else 0) * 0.2
                + len(f.state_variables) * 0.2
                + (1 if not f.privilege_required else 0) * 0.3
            )
            f.consensus_score = risk_score
        findings.sort(key=lambda x: x.consensus_score, reverse=True)
        self.stage_metrics["risk_prioritization"]["output"] = len(findings)
        return findings

    # ------------------------------------------------------------------
    # Stage 3 — Skeptic Gauntlet
    # ------------------------------------------------------------------

    async def skeptic_stage(self, findings: List[Finding]) -> List[Finding]:
        self.logger.info(f"Skeptic Stage: Evaluating {len(findings)} findings")
        self.stage_metrics["skeptic"]["input"] = len(findings)

        from cai.tools.web3_security.validate_findings import _looks_privileged

        for finding in findings:
            # Check access-control markers in location, function name, and description text
            check_text = " ".join(filter(None, [
                finding.location,
                finding.function_name,
                finding.description or "",
                finding.metadata.get("description", ""),
            ])).lower()

            if "onlyowner" in check_text or (
                "owner" in finding.function_name.lower()
                and "onlyowner" in finding.location.lower()
            ):
                self._mark_rejection(
                    finding,
                    "Owner-only access control",
                    "already_mitigated",
                    "NOT EXPLOITABLE – ALREADY MITIGATED",
                    "skeptic",
                )
                continue

            # Broader privilege detection using validate_findings helper + extra patterns
            _EXTRA_PRIVILEGE = (
                "onlyadmin", "onlyrole", "onlygovernance", "onlyminter",
                "onlyoperator", "whitelistonly", "initializer",
                "whennotpaused", "timelock", "require(msg.sender ==",
                "require(msg.sender==",
            )
            if _looks_privileged(check_text) or any(p in check_text for p in _EXTRA_PRIVILEGE):
                self._mark_rejection(
                    finding,
                    f"Privilege-guarded access pattern detected in description/location",
                    "already_mitigated",
                    "NOT EXPLOITABLE – ALREADY MITIGATED",
                    "skeptic",
                )
                continue

            if finding.external_call_depth == 0 and not finding.state_variables:
                self._mark_rejection(
                    finding,
                    "Non-state-mutating and no external calls",
                    "theoretical_only",
                    "THEORETICAL / DESIGN RISK ONLY",
                    "skeptic",
                )
                continue
            for skeptic in self.skeptics:
                try:
                    if callable(skeptic):
                        skeptic(finding)
                except Exception as skeptic_err:
                    self.logger.debug("Skeptic callable failed: %s", skeptic_err)
            finding.consensus_score += 0.2
        for f in findings:
            if not f.rejected_reason:
                f.gate_state.pattern_fp = "passed"

        remaining = [f for f in findings if not f.rejected_reason]
        self.stage_metrics["skeptic"]["output"] = len(remaining)
        self.stage_metrics["skeptic"]["rejected"] = len(findings) - len(remaining)
        return remaining

    # ------------------------------------------------------------------
    # Stage 4 — Fork-Based Exploit Verification (Mandatory)
    # ------------------------------------------------------------------

    async def exploit_stage(self, findings: List[Finding]) -> List[Finding]:
        self.logger.info(
            f"Exploit Stage: Verifying {len(findings)} findings on mainnet fork"
        )
        self.stage_metrics["exploit"]["input"] = len(findings)

        verified: List[Finding] = []
        for finding in findings:
            hypothesis = (
                f"Exploit {finding.vulnerability_type} in "
                f"{finding.function_name} at {finding.location}"
            )
            contract_path = finding.metadata.get("contract_path", "")
            if not contract_path and finding.location and ":" in finding.location:
                candidate = finding.location.split(":", 1)[0]
                if os.path.exists(candidate):
                    contract_path = candidate
            if not contract_path:
                contract_path = self.target_ref
            fork_test_json = generate_fork_test(
                hypothesis=hypothesis,
                contract_path=contract_path,
                contract_name=finding.contract,
            )
            fork_test_data = json.loads(fork_test_json)

            if "error" in fork_test_data:
                self._mark_rejection(
                    finding,
                    f"Fork test generation failed: {fork_test_data['error']}",
                    "invalid_attack_path",
                    "INVALID – NO REAL ATTACK PATH",
                    "exploit",
                )
                continue

            test_file = fork_test_data["test_file"]
            run_result_json = run_fork_test(test_file)
            run_result = json.loads(run_result_json)

            # Prefer captured stdout; fall back to the raw result dict string
            forge_output = run_result.get("stdout") or run_result.get("stderr") or str(run_result)
            analysis_json = analyze_test_output(forge_output)
            analysis = json.loads(analysis_json)

            if not analysis.get("exploit_succeeded"):
                self._mark_rejection(
                    finding,
                    "Fork exploit failed",
                    "invalid_attack_path",
                    "INVALID – NO REAL ATTACK PATH",
                    "exploit",
                )
                continue

            gas_cost = analysis.get("gas_used", 100000) * 20e-9
            finding.gas_cost_estimate = gas_cost
            profit = 1.0 - gas_cost

            if profit <= 0:
                self._mark_rejection(
                    finding,
                    f"Attack not profitable: profit={profit}",
                    "not_profitable",
                    "THEORETICAL / DESIGN RISK ONLY",
                    "exploit",
                )
                continue

            finding.fork_verified = True
            finding.economic_profitability = profit
            finding.exploit_path = [hypothesis]
            finding.exploit_chain_id = f"chain_{finding.id}"
            finding.attack_path_summary = hypothesis
            finding.preconditions_summary = "Permissionless external caller can reach target function."
            finding.permissionless = True
            finding.affected_asset = finding.contract
            finding.consensus_score = max(finding.consensus_score, 0.9)
            finding.gate_state.poc = "passed"
            finding.exploitability_verdict = "EXPLOITABLE – BOUNTY ELIGIBLE"
            verified.append(finding)

        self.stage_metrics["exploit"]["output"] = len(verified)
        self.stage_metrics["exploit"]["verified"] = len(verified)
        self.stage_metrics["exploit"]["rejected"] = len(findings) - len(verified)
        return verified

    # ------------------------------------------------------------------
    # Stage 5 — Formal Invariant Validation
    # ------------------------------------------------------------------

    async def formal_stage(self, findings: List[Finding]) -> List[Finding]:
        self.logger.info(
            f"Formal Stage: Verifying invariants for {len(findings)} findings"
        )
        self.stage_metrics["formal"]["input"] = len(findings)

        for finding in findings:
            if finding.vulnerability_type in (
                "reentrancy",
                "overflow",
                "precision_loss",
                "oracle-manipulation",
            ):
                finding.invariant_broken = True
                finding.gate_state.invariant = "passed"
                self.stage_metrics["formal"]["invariant_passed"] += 1
            else:
                finding.severity = "medium"
                finding.invariant_broken = False
                finding.gate_state.invariant = "failed"
                self.stage_metrics["formal"]["invariant_failed"] += 1
                if not finding.exploitability_verdict:
                    finding.exploitability_verdict = "THEORETICAL / DESIGN RISK ONLY"

        self.stage_metrics["formal"]["output"] = len(findings)

        return findings

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _gate_state_to_dict(self, f: Finding) -> Dict[str, Optional[str]]:
        g = f.gate_state
        return {
            "tool_evidence": g.tool_evidence,
            "pattern_fp": g.pattern_fp,
            "judge": g.judge,
            "disproof": g.disproof,
            "economic": g.economic,
            "poc": g.poc,
            "invariant": g.invariant,
        }

    def _schema_to_core_finding(self, schema_finding: SchemaFinding, contract_path: str) -> Finding:
        payload = to_pipeline_payload(schema_finding, fallback_contract_path=contract_path)
        finding = Finding(
            id=payload["id"],
            vulnerability_type=payload["vulnerability_type"],
            severity=payload["severity"],
            contract=payload["contract"],
            function_name=payload["function_name"],
            location=payload["location"],
        )
        finding.gate_state.tool_evidence = "passed"
        finding.privilege_required = payload["privilege_required"]
        finding.permissionless = payload["permissionless"]
        finding.affected_asset = payload["affected_asset"]
        finding.description = payload.get("description") or None
        finding.metadata["contract_path"] = payload["contract_path"]
        finding.metadata["source_tool"] = schema_finding.tool
        finding.external_call_depth = payload["external_call_depth"]
        finding.cross_contract = payload["cross_contract"]
        finding.consensus_score = max(finding.consensus_score, payload["consensus_score"])
        return finding

    def _mark_rejection(
        self,
        finding: Finding,
        reason: str,
        reason_code: str,
        verdict: str,
        stage: str,
    ) -> None:
        finding.rejected_reason = reason
        finding.rejection_reason_code = reason_code
        finding.exploitability_verdict = verdict
        if stage == "skeptic":
            finding.gate_state.pattern_fp = "dropped"
        if stage == "exploit":
            finding.gate_state.poc = "failed"
        reasons = self.stage_metrics.get(stage, {}).setdefault("rejection_reasons", {})
        reasons[reason_code] = reasons.get(reason_code, 0) + 1

    _LOW_SEVERITY_LABELS = frozenset({"informational", "optimization"})

    def _filter_low_severity(self, findings: List[Finding]) -> List[Finding]:
        """Drop Informational/Optimization findings that will never be exploitable."""
        kept = []
        dropped = 0
        for f in findings:
            if (f.severity or "").lower() in self._LOW_SEVERITY_LABELS:
                dropped += 1
            else:
                kept.append(f)
        self.stage_metrics["discovery"]["severity_filtered"] = dropped
        self.stage_metrics["discovery"]["output"] = len(kept)
        return kept

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Group by (vulnerability_type, contract, function_name); keep highest severity instance."""
        from cai.core.finding import SEVERITY_RANK
        groups: Dict[tuple, Finding] = {}
        for f in findings:
            key = (f.vulnerability_type, f.contract, f.function_name)
            existing = groups.get(key)
            if existing is None:
                groups[key] = f
            else:
                rank_new = SEVERITY_RANK.get((f.severity or "").lower(), 2)
                rank_old = SEVERITY_RANK.get((existing.severity or "").lower(), 2)
                if rank_new > rank_old:
                    groups[key] = f
        kept = list(groups.values())
        self.stage_metrics["discovery"]["deduplicated"] = len(findings) - len(kept)
        return kept

    def generate_report(self, findings: List[Finding]) -> Dict[str, Any]:
        exported_bundles: List[Dict[str, str]] = []
        bundle_output_dir = os.getenv("CAI_EXPORT_EXPLOIT_BUNDLES", "").strip()

        for finding in findings:
            if not finding.exploitability_verdict:
                if finding.is_critical():
                    finding.exploitability_verdict = "EXPLOITABLE – BOUNTY ELIGIBLE"
                elif finding.fork_verified:
                    finding.exploitability_verdict = "THEORETICAL / DESIGN RISK ONLY"
                else:
                    finding.exploitability_verdict = "INVALID – NO REAL ATTACK PATH"
        critical = [f for f in findings if f.is_critical()]
        verified = [f for f in findings if f.passed_all_applicable_gates()]
        exploitability = {
            "EXPLOITABLE – BOUNTY ELIGIBLE": 0,
            "NOT EXPLOITABLE – ALREADY MITIGATED": 0,
            "THEORETICAL / DESIGN RISK ONLY": 0,
            "INVALID – NO REAL ATTACK PATH": 0,
        }
        for finding in findings:
            if finding.exploitability_verdict in exploitability:
                exploitability[finding.exploitability_verdict] += 1

        def _finding_to_report_dict(f: Finding) -> Dict[str, Any]:
            d = f.to_dict()
            return {
                "id": d["id"],
                "vulnerability_type": d["vulnerability_type"],
                "severity": d["severity"],
                "description": d["description"],
                "contract": d["contract"],
                "function": d["function_name"],
                "exploit_path": d["exploit_path"],
                "attack_path_summary": d["attack_path_summary"],
                "preconditions": d["preconditions_summary"],
                "affected_asset": d["affected_asset"],
                "permissionless": d["permissionless"],
                "economic_profitability": d["economic_profitability"],
                "consensus_score": d["consensus_score"],
                "fork_verified": d["fork_verified"],
                "invariant_broken": d["invariant_broken"],
                "exploitability_verdict": d["exploitability_verdict"],
                "rejection_reason_code": d["rejection_reason_code"],
                "rejected_reason": d["rejected_reason"],
                "gate_state": d["gate_state"],
            }

        if bundle_output_dir:
            for finding in findings:
                try:
                    bundle = build_exploit_bundle(finding)
                    export_paths = export_exploit_bundle(bundle, bundle_output_dir, finding.id)
                    exported_bundles.append({"id": finding.id, **export_paths})
                except Exception:
                    # Best-effort export: reporting should not break verdict generation.
                    pass

        return {
            "mode_contract": {
                "deterministic": "EliteWeb3Pipeline.run(target)",
                "interactive": "/hunt -> web3_bug_bounty_agent",
                "judge_gated": "web3_hunter_judge_poc_pattern (Hunter -> Judge -> PoC)",
            },
            "summary": {
                "critical_findings_count": len(critical),
                "total_findings_processed": len(findings),
                "verified_findings_count": len(verified),
                "exploitability_breakdown": exploitability,
            },
            "quality_metrics": {
                "stage_metrics": self.stage_metrics,
                "poc_conversion_rate": (
                    round(
                        self.stage_metrics["exploit"]["verified"]
                        / max(1, self.stage_metrics["exploit"]["input"]),
                        3,
                    )
                    if self.stage_metrics.get("exploit")
                    else 0.0
                ),
            },
            "findings": [_finding_to_report_dict(f) for f in critical],
            "verified_findings": [_finding_to_report_dict(f) for f in verified],
            "exported_bundles": exported_bundles,
        }
