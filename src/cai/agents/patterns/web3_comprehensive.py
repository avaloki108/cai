"""
Web3 game-theoretic audit patterns.

Patterns defined here (same-agent parallel, split context unless noted):

    web3_main_heavy_pattern
        Full 4-stage audit: sensors -> G-CTR reasoning -> validation -> reporting.

    web3_fp_filter_pattern
        FP TRIAGE: false-positive filter for noisy sensor output.

    web3_hunter_judge_poc_pattern
        Hunter (creative) -> Judge Gate (exploitability) -> PoC (survivors).
"""

from cai.repl.commands.parallel import ParallelConfig

# =============================================================================
# Pattern 1 — Web3 Main Heavy (Game-Theoretic 4-Stage)
# =============================================================================
web3_main_heavy_pattern = {
    "name": "web3_main_heavy_pattern",
    "type": "parallel",
    "description": (
        "Main Web3 audit: sensors -> game-theoretic reasoning -> validation -> reporting. "
        "Uses attack-graph correlation and exploit scoring as the selection policy."
    ),
    "unified_context": False,
    "configs": [
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Discovery (Sensors Only). Run slither_analyze (--detect all --json) and "
                "mythril_analyze (-o json). Output structured JSON findings with location, "
                "severity, and evidence. Do NOT score or rank."
            ),
        ),
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: G-CTR Reasoning Core. Run: aggregate_tool_results(), correlate_findings(), "
                "build_attack_graph(), find_exploit_paths(), score_exploit_viability(), "
                "rank_findings_by_exploitability(), generate_strategic_digest(). "
                "Output top 3-5 exploit hypotheses with reasoning and target contracts."
            ),
        ),
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Validation + PoC. Validate top G-CTR hypotheses with Foundry/Hardhat. "
                "Mark each: CONFIRMED / FALSE_POSITIVE / NEEDS_MORE_INFO."
            ),
        ),
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Reporting. Run council_filter_findings() on validated results. "
                "Report ONLY council-validated permissionless issues with exploit chains, "
                "impact, PoC steps, and remediation. Needs Evidence section for the rest."
            ),
        ),
    ],
}

# =============================================================================
# Pattern 2 — FP TRIAGE: False-Positive Filter
# =============================================================================
web3_fp_filter_pattern = {
    "name": "web3_fp_filter_pattern",
    "type": "parallel",
    "description": (
        "FP TRIAGE: False-Positive Filter. Runs triage reproduction, correlation "
        "scoring, and council-gated reporting. Feed this pattern noisy sensor output "
        "to distill a high-confidence finding set."
    ),
    "unified_context": False,
    "configs": [
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: FP Triage. Reproduce each finding quickly. "
                "Output per issue: CONFIRMED / NEEDS_MORE_INFO / FALSE_POSITIVE."
            ),
        ),
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Correlation + Scoring. Run aggregate_tool_results(), "
                "correlate_findings(), build_attack_graph(), find_exploit_paths(), "
                "score_exploit_viability(), rank_findings_by_exploitability(), "
                "generate_strategic_digest(). Output a small, high-confidence set."
            ),
        ),
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Clean Reporting. Include only CONFIRMED and high-likelihood "
                "NEEDS_MORE_INFO findings. Council-gate with council_filter_findings(). "
                "De-duplicate across tools. Needs Evidence section for the rest."
            ),
        ),
    ],
}

# =============================================================================
# Pattern 3 — Hunter -> Judge Gate -> PoC
# =============================================================================
web3_hunter_judge_poc_pattern = {
    "name": "web3_hunter_judge_poc_pattern",
    "type": "parallel",
    "description": (
        "Hunter (creative) -> Judge Gate (exploitability filter) -> PoC (survivors only). "
        "Hunter outputs CANDIDATES_JSON; Judge outputs verdicts; "
        "only EXPLOITABLE -- BOUNTY ELIGIBLE go to PoC."
    ),
    "unified_context": False,
    "configs": [
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Hunter (Phase A). Be creative and expansive. Output candidates in "
                'CANDIDATES_JSON format: { "candidates": [ { "title", "hypothesis", '
                '"affected_code", "suspected_attack" } ] }. Do NOT judge -- output many candidates.'
            ),
        ),
        ParallelConfig(
            "defi_bounty_judge_agent",
            prompt=(
                "ROLE: Judge Gate (Phase B). Evaluate CANDIDATES_JSON. Require concrete "
                "call sequence with named functions and state preconditions. "
                "Verdicts: EXPLOITABLE -- BOUNTY ELIGIBLE, or INVALID -- NO REAL ATTACK PATH."
            ),
        ),
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: PoC Builder (Phase C). Build Foundry tests / minimal tx sequences "
                "ONLY for EXPLOITABLE -- BOUNTY ELIGIBLE issues. Confirm measurable impact."
            ),
        ),
    ],
}
