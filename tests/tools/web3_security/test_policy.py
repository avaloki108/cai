from __future__ import annotations

import pytest

from cai.tools.web3_security.policy import evaluate_policy, parse_policy_level
from cai.tools.web3_security.schemas import ChainType, RiskLevel, Web3PluginMetadata


def _metadata(**overrides):
    base = Web3PluginMetadata(
        name="test_plugin",
        description="Test plugin",
        category="validation",
        risk_level=RiskLevel.BALANCED,
        requires_aggressive=False,
        input_schema={"type": "object", "properties": {}},
        supports_fork_test=False,
        supports_formal_verification=False,
        mutates_state=False,
        chain_type=ChainType.EVM,
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def test_parse_policy_level_roundtrip():
    assert parse_policy_level("safe") == RiskLevel.SAFE
    assert parse_policy_level("balanced") == RiskLevel.BALANCED
    assert parse_policy_level("aggressive") == RiskLevel.AGGRESSIVE


def test_parse_policy_level_rejects_unknown():
    with pytest.raises(ValueError):
        parse_policy_level("invalid")


def test_evaluate_policy_blocks_low_level():
    metadata = _metadata(risk_level=RiskLevel.AGGRESSIVE)
    allowed, reason, required_flags = evaluate_policy(
        metadata=metadata,
        policy_level=RiskLevel.BALANCED,
        allow_aggressive=True,
    )
    assert not allowed
    assert "too low" in (reason or "").lower()
    assert required_flags["minimum_policy_level"] == "aggressive"


def test_evaluate_policy_requires_allow_aggressive():
    metadata = _metadata(risk_level=RiskLevel.AGGRESSIVE, requires_aggressive=True)
    allowed, reason, required_flags = evaluate_policy(
        metadata=metadata,
        policy_level=RiskLevel.AGGRESSIVE,
        allow_aggressive=False,
    )
    assert not allowed
    assert "allow_aggressive" in (reason or "")
    assert required_flags["allow_aggressive_required"] is True


def test_evaluate_policy_blocks_state_mutation_in_safe_mode():
    metadata = _metadata(mutates_state=True, risk_level=RiskLevel.SAFE)
    allowed, reason, _ = evaluate_policy(
        metadata=metadata,
        policy_level=RiskLevel.SAFE,
        allow_aggressive=False,
    )
    assert not allowed
    assert "state-mutating" in (reason or "").lower()

