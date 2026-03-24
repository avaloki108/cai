from __future__ import annotations

from typing import Any, Dict, Tuple

from cai.tools.web3_security.schemas import (
    ExposureSurface,
    RiskLevel,
    Web3PluginMetadata,
)


RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.BALANCED: 1,
    RiskLevel.AGGRESSIVE: 2,
}


# Not every registered plugin must be available from every surface.
AGENT_EXPOSED_PLUGINS = {
    "false_positive_filter",
    "normalize_finding_dict",
}

MCP_EXPOSED_PLUGINS = {
    "false_positive_filter",
    "normalize_finding_dict",
}


def parse_policy_level(policy_level: str | RiskLevel) -> RiskLevel:
    if isinstance(policy_level, RiskLevel):
        return policy_level
    value = str(policy_level).strip().lower()
    if value == "safe":
        return RiskLevel.SAFE
    if value == "balanced":
        return RiskLevel.BALANCED
    if value == "aggressive":
        return RiskLevel.AGGRESSIVE
    raise ValueError(f"Unknown policy level: {policy_level}")


def is_plugin_exposed(plugin_name: str, surface: ExposureSurface) -> bool:
    if surface == ExposureSurface.ANY:
        return plugin_name in (AGENT_EXPOSED_PLUGINS | MCP_EXPOSED_PLUGINS)
    if surface == ExposureSurface.MCP:
        return plugin_name in MCP_EXPOSED_PLUGINS
    return plugin_name in AGENT_EXPOSED_PLUGINS


def evaluate_policy(
    metadata: Web3PluginMetadata,
    policy_level: RiskLevel,
    allow_aggressive: bool,
) -> Tuple[bool, str | None, Dict[str, Any]]:
    required_flags: Dict[str, Any] = {
        "allow_aggressive_required": metadata.requires_aggressive,
        "minimum_policy_level": metadata.risk_level.value,
    }
    if metadata.requires_aggressive and not allow_aggressive:
        return False, "Plugin requires allow_aggressive=true.", required_flags

    requested_rank = RISK_ORDER[policy_level]
    plugin_rank = RISK_ORDER[metadata.risk_level]
    if requested_rank < plugin_rank:
        return (
            False,
            f"Policy level '{policy_level.value}' is too low for plugin risk '{metadata.risk_level.value}'.",
            required_flags,
        )

    # State mutating actions are intentionally not permitted in safe mode.
    if metadata.mutates_state and policy_level == RiskLevel.SAFE:
        return False, "State-mutating plugin is blocked under safe policy.", required_flags

    return True, None, required_flags

