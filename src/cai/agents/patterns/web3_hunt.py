"""Web3-focused parallel hunting patterns.

These patterns are optimized for local smart contract audits (Solidity/Hardhat/Foundry)
with a split between discovery and verification.

Note: Dict-based patterns are discovered automatically when the variable name ends
with `_pattern`.
"""

from cai.repl.commands.parallel import ParallelConfig


web3_hunt_pattern = {
    "name": "web3_hunt_pattern",
    "type": "parallel",
    "description": (
        "Web3 exploit-hunting: discovery (bug_bounter) + verification (retester) "
        "+ optional generic executor (one_tool) + reporting."
    ),
    # Keep contexts split by default to reduce cross-contamination.
    # (Agents still see the same user prompt and can be coordinated via custom prompts.)
    "unified_context": False,
    "configs": [
        # Primary discovery: has web3 security tools (Slither/Mythril/etc.)
        ParallelConfig(
            "bug_bounter_agent",
            prompt=(
                "ROLE: Discovery. Use the user's MAIN PROMPT as the source of truth for target + scope. "
                "Prioritize high-impact, exploitable smart-contract issues (auth/upgrade/init, oracle misuse, accounting, "
                "reentrancy, signature/replay, precision/decimals). Provide exact file+function pointers and a minimal local "
                "repro strategy. Validate automated-tool findings; avoid noisy low-confidence output."
            ),
        ),
        # Triage/verification: confirm exploitability, reduce false positives
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Triage/Verification. Take top candidate issues from other agents and attempt to confirm locally. "
                "Output per issue: CONFIRMED / NEEDS-MORE-INFO / FALSE-POSITIVE, with evidence and a concrete repro plan. "
                "Prefer definitive conclusions over speculation."
            ),
        ),
        # Optional: generic Linux command executor for build/test plumbing
        ParallelConfig(
            "one_tool_agent",
            prompt=(
                "ROLE: Build/Test runner. Run non-interactive local commands to support the audit (e.g., tests, build, slither, mythril). "
                "IMPORTANT: run commands workspace-relative (via /workspace exec when in CAI) and choose commands that emit output "
                "periodically to avoid idle timeouts. Do not run anything against live networks."
            ),
        ),
        # Optional: generate a clean consolidated report at the end
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Consolidation. Summarize the final results across agents into a single findings table. "
                "De-duplicate, highlight the top confirmed issues first, and separate confirmed vs unconfirmed."
            ),
        ),
    ],
}


web3_hunt_heavy_pattern = {
    "name": "web3_hunt_heavy_pattern",
    "type": "parallel",
    "description": (
        "Web3 exploit-hunting (heavy): 3x bug_bounter focus lanes + retester + executor. "
        "Best for deeper smart-contract audits."
    ),
    "unified_context": False,
    "configs": [
        ParallelConfig(
            "bug_bounter_agent",
            prompt=(
                "FOCUS LANE A (Oracle/Price Integrity). Use the MAIN PROMPT for target/scope. Trace external data ingestion "
                "(price/oracle/messages) -> normalization/decimals -> staleness/deadline -> authorization/signing -> consumers. "
                "Prioritize exploitable paths where an attacker can influence critical decisions (liquidation/margin/settlement/fees)."
            ),
        ),
        ParallelConfig(
            "bug_bounter_agent",
            prompt=(
                "FOCUS LANE B (Accounting/Invariants). Use the MAIN PROMPT for target/scope. Look for invariant breaks: share math, "
                "margin/PnL, funding/fees, liquidation thresholds, rounding/precision, signed math edge cases, state desync. "
                "Prioritize fund loss/insolvency and reproducible bugs."
            ),
        ),
        ParallelConfig(
            "bug_bounter_agent",
            prompt=(
                "FOCUS LANE C (Auth/Upgrade/Init). Use the MAIN PROMPT for target/scope. Check role gating, admin paths, proxy/implementation "
                "patterns, initializer misuse, delegatecall hazards, and permissioned parameter changes. Prioritize privilege escalation and fund-drain paths."
            ),
        ),
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Triage/Verification. Pick the top 3 candidate issues (highest severity * highest confidence) and try to confirm locally. "
                "Mark CONFIRMED / NEEDS-MORE-INFO / FALSE-POSITIVE, with evidence and a concrete minimal repro plan."
            ),
        ),
        ParallelConfig(
            "one_tool_agent",
            prompt=(
                "ROLE: Build/Test runner. Support other agents by running non-interactive local commands (hardhat/foundry/slither/mythril/tests). "
                "Use workspace-relative paths (prefer /workspace exec in CAI). Avoid long silent compiles (emit output) and do not touch live endpoints."
            ),
        ),
    ],
}
