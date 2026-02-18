"""
Web3 Sequential Audit Pattern

Properly staged pipeline where each agent runs AFTER the previous one
finishes, with explicit data handoff between stages.

Stages:
    1. Discovery Agent  → runs sensors, outputs DISCOVERY_FINDINGS_JSON
    2. G-CTR Agent      → reasons over findings, outputs GCTR_DIGEST_JSON
    3. Validator/PoC    → tests top hypotheses, outputs CONFIRMED/FP verdicts
    4. Reporter         → consolidates into final report

Also provides parallel variants where agents within the same phase
can run simultaneously, but phases are sequential.

Usage:
    /agent web3_discovery_gctr_pattern      # Discovery + G-CTR (2 phases)
    /agent web3_full_sequential_pattern     # All 4 phases
    /agent web3_discovery_judge_poc_pattern  # Discovery + Judge Gate + PoC
"""

from cai.repl.commands.parallel import ParallelConfig


# =============================================================================
# Pattern 1: Discovery → G-CTR (Core 2-Phase)
# =============================================================================
web3_discovery_gctr_pattern = {
    "name": "web3_discovery_gctr_pattern",
    "type": "parallel",
    "description": (
        "2-phase audit: Discovery Agent runs sensors, then G-CTR Agent "
        "reasons over findings with attack graphs and exploit scoring. "
        "Run Discovery first, merge histories, then G-CTR processes the output."
    ),
    "unified_context": True,  # G-CTR needs to see Discovery output
    "configs": [
        # Phase 1: Discovery - sensors only
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1). You run FIRST. "
                "Run static analysis with slither_analyze (--detect all --json) and "
                "symbolic execution with mythril_analyze (-o json). "
                "Also run securify_analyze if available. "
                "Focus on: reentrancy, access control, upgradeability, initialization, "
                "oracle issues, arithmetic, external calls. "
                "Output DISCOVERY_FINDINGS_JSON with ALL findings, locations, and code snippets. "
                "Do NOT score, rank, or judge exploitability."
            ),
        ),
        # Phase 2: G-CTR - reasoning core
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR Reasoning Core (Phase 2). You run AFTER Discovery. "
                "Take the DISCOVERY_FINDINGS_JSON from the Discovery Agent and: "
                "1) aggregate_tool_results() to combine and deduplicate "
                "2) correlate_findings() to find multi-tool confirmations "
                "3) build_attack_graph() to map exploit chains "
                "4) find_exploit_paths() to identify viable paths "
                "5) score_exploit_viability() + rank_findings_by_exploitability() "
                "6) generate_strategic_digest() with top 3-5 hypotheses "
                "Output: GCTR_DIGEST_JSON with scored, prioritized hypotheses."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 2: Full Sequential (4-Phase Pipeline)
# =============================================================================
web3_full_sequential_pattern = {
    "name": "web3_full_sequential_pattern",
    "type": "parallel",
    "description": (
        "Full 4-phase audit pipeline: Discovery → G-CTR → Validation → Reporting. "
        "Use unified context so each phase sees the previous phase's output. "
        "Run phases in order: Discovery first, then merge and run G-CTR, etc."
    ),
    "unified_context": True,  # All phases see accumulated context
    "configs": [
        # Phase 1: Discovery
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1/4). Run ALL sensors: "
                "slither_analyze, mythril_analyze, securify_analyze. "
                "Output DISCOVERY_FINDINGS_JSON with structured findings."
            ),
        ),
        # Phase 2: G-CTR
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR (Phase 2/4). Take Discovery findings and produce "
                "GCTR_DIGEST_JSON with attack graphs, exploit scoring, and "
                "top 3-5 prioritized hypotheses for validation."
            ),
        ),
        # Phase 3: Validation
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Validator (Phase 3/4). Take GCTR_DIGEST_JSON hypotheses and: "
                "1) Attempt Foundry/Hardhat PoC for each top hypothesis "
                "2) Mark each as CONFIRMED / FALSE_POSITIVE / NEEDS_MORE_INFO "
                "3) For CONFIRMED, include reproduction steps "
                "Output: Validation results with verdicts per hypothesis."
            ),
        ),
        # Phase 4: Reporting
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Reporter (Phase 4/4). Consolidate all outputs: "
                "Discovery findings + G-CTR digest + Validation results. "
                "Report ONLY validated findings with: "
                "severity, exploit chain, impact, PoC steps, remediation. "
                "Include a Needs Evidence section for unvalidated hypotheses."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 3: Discovery → Judge Gate → PoC (Exploitability Pipeline)
# =============================================================================
web3_discovery_judge_poc_pattern = {
    "name": "web3_discovery_judge_poc_pattern",
    "type": "parallel",
    "description": (
        "3-phase pipeline: Discovery runs sensors → G-CTR scores and outputs "
        "CANDIDATES_JSON → Judge Gate filters to EXPLOITABLE only → PoC for survivors. "
        "Combines sensor precision with exploitability-first judging."
    ),
    "unified_context": True,
    "configs": [
        # Phase 1: Discovery + G-CTR combined
        ParallelConfig(
            "web3_discovery_agent",
            prompt=(
                "ROLE: Discovery (Phase 1). Run sensors and output "
                "DISCOVERY_FINDINGS_JSON with all raw findings."
            ),
        ),
        # Phase 2: G-CTR produces candidates for Judge
        ParallelConfig(
            "web3_gctr_agent",
            prompt=(
                "ROLE: G-CTR + Candidate Generator (Phase 2). "
                "Take Discovery findings, run correlation and scoring, "
                "then output CANDIDATES_JSON for the Judge Gate. Format: "
                '{ "candidates": [ { "title", "hypothesis", '
                '"affected_code", "suspected_attack" } ] }. '
                "Be expansive - the Judge will filter."
            ),
        ),
        # Phase 3: Judge Gate
        ParallelConfig(
            "defi_bounty_judge_agent",
            prompt=(
                "ROLE: Judge Gate (Phase 3). Evaluate CANDIDATES_JSON. "
                "For each candidate: does this exploit work NOW in current code? "
                "Require concrete call sequence with named functions. "
                "Output verdicts: only EXPLOITABLE – BOUNTY ELIGIBLE get promoted."
            ),
        ),
        # Phase 4: PoC for survivors
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: PoC Builder (Phase 4). Build Foundry tests / minimal tx "
                "sequences ONLY for issues marked EXPLOITABLE – BOUNTY ELIGIBLE "
                "by the Judge. Confirm impact is measurable."
            ),
        ),
    ],
}
