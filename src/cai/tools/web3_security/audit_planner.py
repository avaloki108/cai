"""
Web3 audit planner for streamlined workflows.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from cai.sdk.agents import function_tool
from .config import get_available_tools


def _risk_profile(depth: str, time_budget: int) -> str:
    if depth:
        depth = depth.lower()
    if depth in ["quick", "balanced", "deep"]:
        return depth
    if time_budget <= 90:
        return "quick"
    if time_budget >= 360:
        return "deep"
    return "balanced"


def _focus_from_context(context: Dict[str, Any]) -> List[str]:
    focus = ["access_control", "reentrancy", "upgradeability", "external_calls"]
    signals = context.get("signals", {})
    defi = signals.get("defi", {})
    if defi.get("oracle") or defi.get("chainlink"):
        focus.append("oracle_manipulation")
    if defi.get("lending"):
        focus.extend(["liquidation", "collateral_invariants"])
    if defi.get("vault"):
        focus.extend(["share_accounting", "erc4626_rounding"])
    if defi.get("bridge"):
        focus.extend(["bridge_message_validation", "replay_protection"])
    if defi.get("uniswap_v2") or defi.get("uniswap_v3") or defi.get("curve"):
        focus.extend(["amm_price_manipulation", "mev_sandwich"])
    return list(dict.fromkeys(focus))


@function_tool
def plan_web3_audit(
    repo_context: str = "",
    goals: str = "",
    risk_depth: str = "",
    time_budget_minutes: int = 240,
    include_dynamic: bool = True,
    ctf=None,
) -> str:
    """
    Build a Web3 audit plan based on repo context and constraints.

    Args:
        repo_context: JSON string from detect_web3_repo_context().
        goals: Optional audit goals or scope constraints.
        risk_depth: quick | balanced | deep (auto-selected if empty).
        time_budget_minutes: Total time budget.
        include_dynamic: Include fuzzing/symbolic phases when True.

    Returns:
        JSON string describing the audit plan and recommended tools.
    """
    context = {}
    if repo_context:
        try:
            context = json.loads(repo_context)
        except Exception:
            context = {}

    depth = _risk_profile(risk_depth, time_budget_minutes)
    focus = _focus_from_context(context)
    tooling = get_available_tools()

    phases: List[Dict[str, Any]] = []
    phases.append({
        "phase": "context",
        "focus": ["architecture", "trust_boundaries"],
        "recommended_tools": ["detect_web3_repo_context", "web3_tool_status", "web3_kb_query"],
        "notes": "Confirm framework, upgradeability, oracles, and protocol type.",
    })
    phases.append({
        "phase": "static_analysis",
        "focus": focus,
        "recommended_tools": [
            "slither_analyze",
            "slither_check_upgradeability",
            "securify_analyze",
        ],
        "notes": "Run with JSON output and feed into aggregate_tool_results().",
    })

    if include_dynamic:
        phases.append({
            "phase": "symbolic",
            "focus": ["path_exploration", "edge_cases"],
            "recommended_tools": ["mythril_analyze", "gambit_analyze", "oyente_analyze"],
            "notes": "Use targeted runs on critical contracts to avoid path explosion.",
        })
        phases.append({
            "phase": "fuzzing",
            "focus": ["property_tests", "coverage"],
            "recommended_tools": ["echidna_fuzz", "medusa_fuzz"],
            "notes": "Prioritize invariants around transfers, accounting, and access control.",
        })

    if depth == "deep":
        phases.append({
            "phase": "formal_verification",
            "focus": ["invariants", "critical_paths"],
            "recommended_tools": ["certora_verify"],
            "notes": "Use formal checks for core accounting and upgrade authorization.",
        })

    phases.append({
        "phase": "correlation_scoring",
        "focus": ["dedup", "confidence", "exploitability"],
        "recommended_tools": [
            "aggregate_tool_results",
            "correlate_findings",
            "build_attack_graph",
            "find_exploit_paths",
            "score_exploit_viability",
            "rank_findings_by_exploitability",
        ],
        "notes": "Prioritize by exploitability and economic payoff.",
    })
    phases.append({
        "phase": "council_gate",
        "focus": ["false_positive_filtering", "permissionless", "evidence"],
        "recommended_tools": ["council_filter_findings"],
        "notes": "Run council-based filtering before any reporting output.",
    })
    phases.append({
        "phase": "reporting",
        "focus": ["validated_findings", "remediation"],
        "recommended_tools": ["generate_strategic_digest", "web3_memory_add"],
        "notes": "Store validated insights for future audits.",
    })

    return json.dumps({
        "goals": goals,
        "risk_depth": depth,
        "time_budget_minutes": time_budget_minutes,
        "focus_areas": focus,
        "tooling_available": tooling,
        "phases": phases,
    }, indent=2)
