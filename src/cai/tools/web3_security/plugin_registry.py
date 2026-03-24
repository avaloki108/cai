from __future__ import annotations

import json
from typing import Any, Dict, List

from cai.tools.web3_security.finding_schema import ensure_finding_dict
from cai.tools.web3_security.schemas import (
    ChainType,
    RiskLevel,
    Web3Plugin,
    Web3PluginMetadata,
)
from cai.tools.web3_security.validate_findings import _filter_false_positives_impl


class Web3PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, Web3Plugin] = {}

    def register(self, plugin: Web3Plugin) -> None:
        self._plugins[plugin.metadata.name] = plugin

    def unregister(self, plugin_name: str) -> None:
        self._plugins.pop(plugin_name, None)

    def get(self, plugin_name: str) -> Web3Plugin:
        plugin = self._plugins.get(plugin_name)
        if not plugin:
            raise KeyError(f"Unknown Web3 plugin: {plugin_name}")
        return plugin

    def list(self) -> List[Web3Plugin]:
        return list(self._plugins.values())

    def clear(self) -> None:
        self._plugins.clear()


REGISTRY = Web3PluginRegistry()


def _run_false_positive_filter(args: Dict[str, Any]) -> Dict[str, Any]:
    findings = args.get("findings", [])
    if isinstance(findings, str):
        findings_json = findings
    else:
        findings_json = json.dumps(findings)

    return _filter_false_positives_impl(
        findings_json=findings_json,
        tool_source=str(args.get("tool_source", "slither")),
        min_confidence=float(args.get("min_confidence", 0.5)),
    )


def _normalize_finding_dict(args: Dict[str, Any]) -> Dict[str, Any]:
    finding = args.get("finding", {})
    if not isinstance(finding, dict):
        raise ValueError("finding must be a JSON object")
    normalized = ensure_finding_dict(finding)
    return {"normalized_finding": normalized}


def register_builtin_web3_plugins() -> None:
    REGISTRY.register(
        Web3Plugin(
            metadata=Web3PluginMetadata(
                name="false_positive_filter",
                description="Filter noisy findings and return exploitability-focused candidates.",
                category="validation",
                risk_level=RiskLevel.SAFE,
                requires_aggressive=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "findings": {"type": ["array", "string"]},
                        "tool_source": {"type": "string", "default": "slither"},
                        "min_confidence": {"type": "number", "default": 0.5},
                    },
                    "required": ["findings"],
                },
                supports_fork_test=False,
                supports_formal_verification=False,
                mutates_state=False,
                chain_type=ChainType.MULTI,
            ),
            execute=_run_false_positive_filter,
        )
    )
    REGISTRY.register(
        Web3Plugin(
            metadata=Web3PluginMetadata(
                name="normalize_finding_dict",
                description="Normalize a finding object to the canonical finding schema shape.",
                category="normalization",
                risk_level=RiskLevel.SAFE,
                requires_aggressive=False,
                input_schema={
                    "type": "object",
                    "properties": {"finding": {"type": "object"}},
                    "required": ["finding"],
                },
                supports_fork_test=False,
                supports_formal_verification=False,
                mutates_state=False,
                chain_type=ChainType.MULTI,
            ),
            execute=_normalize_finding_dict,
        )
    )


register_builtin_web3_plugins()

