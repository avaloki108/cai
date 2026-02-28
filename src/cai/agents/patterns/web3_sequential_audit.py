"""
Web3 Sequential Audit Patterns (specialist agents, unified context).

Unlike web3_main_heavy_pattern (same agent with split context), these
patterns use dedicated specialist agents and unified context so each
phase sees the previous phase's output.

Patterns:

    web3_discovery_gctr_pattern
        Lightweight 2-phase: Discovery sensors -> G-CTR reasoning.

    web3_full_sequential_pattern
        Full 4-phase pipeline with specialist agents and sequential handoff.

    web3_discovery_judge_poc_pattern
        3-phase: Discovery sensors -> G-CTR + Judge Gate -> PoC survivors.
"""

from cai.repl.commands.parallel import ParallelConfig


# =============================================================================
# Pattern 1 — Discovery + G-CTR (2-Phase)
# =============================================================================
web3_discovery_gctr_pattern = {
    "name": "web3_discovery_gctr_pattern",
    "type": "parallel",
    "description": (
        "2-phase audit: Discovery Agent runs sensors, then G-CTR Agent reasons "
        "over findings with attack graphs and exploit scoring. "
        "Run Discovery first, merge histories, then G-CTR processes the output."
    ),
    "unified_context": True,
    "configs": [
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1). Run slither_analyze (--detect all --json), "
                "mythril_analyze (-o json), securify_analyze. "
                "Output DISCOVERY_FINDINGS_JSON with all findings and code snippets. "
                "Do NOT score or judge exploitability."
            ),
        ),
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR Reasoning (Phase 2). Take DISCOVERY_FINDINGS_JSON and run: "
                "aggregate_tool_results(), correlate_findings(), build_attack_graph(), "
                "find_exploit_paths(), score_exploit_viability(), "
                "rank_findings_by_exploitability(), generate_strategic_digest(). "
                "Output GCTR_DIGEST_JSON with top 3-5 scored hypotheses."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 2 — Full Sequential (4-Phase, Specialist Agents)
# =============================================================================
web3_full_sequential_pattern = {
    "name": "web3_full_sequential_pattern",
    "type": "parallel",
    "description": (
        "Full 4-phase audit with specialist agents and sequential handoff "
        "(unified context): Discovery -> G-CTR -> Validation -> Reporting. "
        "Each agent is purpose-built for its phase."
    ),
    "unified_context": True,
    "configs": [
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1/4). Run ALL sensors: slither_analyze, "
                "mythril_analyze, securify_analyze. Output DISCOVERY_FINDINGS_JSON."
            ),
        ),
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR (Phase 2/4). Take Discovery findings, produce "
                "GCTR_DIGEST_JSON with attack graphs, exploit scoring, and "
                "top 3-5 prioritized hypotheses."
            ),
        ),
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Validator (Phase 3/4). Attempt Foundry/Hardhat PoC for each "
                "top GCTR_DIGEST_JSON hypothesis. Mark: CONFIRMED / FALSE_POSITIVE / "
                "NEEDS_MORE_INFO with reproduction steps."
            ),
        ),
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Reporter (Phase 4/4). Consolidate Discovery + G-CTR + Validation. "
                "Report ONLY validated findings with severity, exploit chain, impact, "
                "PoC steps, remediation. Needs Evidence section for the rest."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 3 — Discovery + Judge Gate + PoC (Exploitability Pipeline)
# =============================================================================
web3_discovery_judge_poc_pattern = {
    "name": "web3_discovery_judge_poc_pattern",
    "type": "parallel",
    "description": (
        "3-phase pipeline: Discovery runs sensors -> G-CTR scores and outputs "
        "CANDIDATES_JSON -> Judge Gate filters to EXPLOITABLE only -> PoC for survivors. "
        "Combines sensor precision with exploitability-first judging."
    ),
    "unified_context": True,
    "configs": [
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1). Run sensors, output "
                "DISCOVERY_FINDINGS_JSON with all raw findings."
            ),
        ),
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR + Candidate Generator (Phase 2). Run correlation "
                "and scoring on Discovery findings, then output CANDIDATES_JSON: "
                '{ "candidates": [ { "title", "hypothesis", '
                '"affected_code", "suspected_attack" } ] }. Be expansive.'
            ),
        ),
        ParallelConfig(
            "defi_bounty_judge_agent",
            prompt=(
                "ROLE: Judge Gate (Phase 3). Evaluate CANDIDATES_JSON. "
                "Require concrete call sequence with named functions. "
                "Only EXPLOITABLE -- BOUNTY ELIGIBLE get promoted."
            ),
        ),
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: PoC Builder (Phase 4). Build Foundry tests / minimal tx "
                "sequences ONLY for EXPLOITABLE -- BOUNTY ELIGIBLE issues."
            ),
        ),
    ],
}
