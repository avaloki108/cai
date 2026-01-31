import json

from cai.tools.web3_security.validate_findings import council_filter_findings


def _run_filter(findings):
    return json.loads(council_filter_findings(json.dumps(findings)))


def _base_finding():
    return {
        "title": "Reentrancy in withdraw",
        "target_asset": "Vault",
        "vulnerability_class": "reentrancy",
        "exact_endpoint_or_component": "Vault.withdraw",
        "preconditions": "permissionless public caller",
        "reproduction_steps": ["call withdraw twice in same tx"],
        "expected_vs_observed": "expected single withdrawal, observed double withdrawal",
        "impact_statement": "attacker drains funds",
        "proof_artifacts": ["tx_trace_1", "poc_script.py"],
        "permissionless": True,
    }


def test_validated_permissionless_with_evidence():
    findings = [_base_finding()]
    result = _run_filter(findings)
    assert result["summary"]["validated"] == 1
    assert result["summary"]["needs_evidence"] == 0
    assert result["summary"]["rejected"] == 0


def test_rejects_non_permissionless_explicit():
    finding = _base_finding()
    finding["permissionless"] = False
    findings = [finding]
    result = _run_filter(findings)
    assert result["summary"]["validated"] == 0
    assert result["summary"]["rejected"] == 1


def test_rejects_privileged_preconditions():
    finding = _base_finding()
    finding.pop("permissionless")
    finding["preconditions"] = "onlyAdmin can call initialize"
    findings = [finding]
    result = _run_filter(findings)
    assert result["summary"]["validated"] == 0
    assert result["summary"]["rejected"] == 1


def test_needs_evidence_when_missing_fields():
    finding = _base_finding()
    finding.pop("proof_artifacts")
    findings = [finding]
    result = _run_filter(findings)
    assert result["summary"]["validated"] == 0
    assert result["summary"]["needs_evidence"] == 1
