"""
Web3 Comprehensive Auditing Patterns

Multi-agent patterns optimized for thorough web3 security audits.
Combines discovery, fuzzing, validation, and reporting agents working in parallel.

Architecture:
- Discovery Agent: Static + symbolic analysis (Slither, Mythril, Securify)
- Fuzzing Agent: Property-based + coverage-guided fuzzing (Echidna, Medusa)
- Validation Agent: Triage, false positive filtering, exploit scoring
- Reporting Agent: Consolidation, strategic digest, final report

All patterns use split context by default to avoid cross-contamination,
but agents can be configured to share context for collaborative analysis.
"""

from cai.repl.commands.parallel import ParallelConfig


# =============================================================================
# Pattern 1: Web3 Comprehensive (Full Stack)
# =============================================================================
web3_comprehensive_pattern = {
    "name": "web3_comprehensive_pattern",
    "type": "parallel",
    "description": (
        "Full-stack Web3 audit: discovery (static+symbolic) + fuzzing + "
        "validation (exploit scoring) + reporting. Best for thorough audits."
    ),
    "unified_context": False,
    "configs": [
        # Discovery agent - static + symbolic analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Discovery (Static + Symbolic). Use the MAIN PROMPT for target/scope. "
                "Run static analysis with slither_analyze (--detect all --json) and "
                "symbolic execution with mythril_analyze (-o json). "
                "Focus on: reentrancy, access control, upgradeability, initialization, oracle issues. "
                "Use filter_false_positives() to reduce noise. "
                "Output: Structured findings with location, severity, and preliminary exploit assessment."
            ),
        ),
        # Fuzzing agent - property-based + coverage-guided
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Fuzzing Campaign. Use the MAIN PROMPT for target/scope. "
                "Run property-based fuzzing with echidna_fuzz() and coverage-guided "
                "fuzzing with medusa_fuzz(). Focus on invariant violations, assertion failures, "
                "and unexpected state transitions. "
                "If time-constrained, prioritize echidna_fuzz with --test-limit 10000. "
                "Output: Fuzzing results with reproduction steps and coverage metrics."
            ),
        ),
        # Validation agent - triage + scoring
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Validation + Scoring. Take findings from other agents and: "
                "1. Use validate_finding() and filter_false_positives() to confirm validity. "
                "2. Use score_exploit_viability() to calculate payoff/effort scores. "
                "3. Use rank_findings_by_exploitability() to prioritize. "
                "4. Check for multi-step exploit chains with find_exploit_paths(). "
                "Output per finding: CONFIRMED/FALSE_POSITIVE/NEEDS_INFO + exploit_score + reasoning."
            ),
        ),
        # Reporting agent - consolidation + strategic digest
        ParallelConfig(
            "reporting_agent",
            prompt=(
                "ROLE: Reporting + Strategic Digest. Consolidate findings from all agents: "
                "1. Use aggregate_tool_results() to combine outputs. "
                "2. Use correlate_findings() to identify multi-tool confirmations. "
                "3. Use generate_strategic_digest() for prioritized action plan. "
                "Output: Final report with severity rankings, exploit chains, "
                "economic impact estimates, and remediation recommendations."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 2: Web3 Quick Scan (Time-constrained)
# =============================================================================
web3_quick_scan_pattern = {
    "name": "web3_quick_scan_pattern",
    "type": "parallel",
    "description": (
        "Quick Web3 security scan: fast static analysis + validation. "
        "Best for initial reconnaissance or time-constrained assessments."
    ),
    "unified_context": False,
    "configs": [
        # Fast discovery
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Fast Discovery. Use the MAIN PROMPT for target/scope. "
                "Run quick static analysis with slither_analyze (--print human-summary). "
                "Focus only on HIGH and CRITICAL severity findings. "
                "Skip symbolic execution and fuzzing for speed. "
                "Use filter_false_positives(min_confidence=0.7) to reduce noise. "
                "Output: Top 10 highest-priority findings with locations."
            ),
        ),
        # Quick validation
        ParallelConfig(
            "retester_agent",
            prompt=(
                "ROLE: Quick Validation. Take top findings and: "
                "1. Validate only HIGH/CRITICAL severity findings. "
                "2. Use score_exploit_viability() for quick scoring. "
                "3. Focus on immediately exploitable issues. "
                "Output: Validated findings with exploit feasibility assessment."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 3: Web3 Deep Dive (Single Contract)
# =============================================================================
web3_deep_dive_pattern = {
    "name": "web3_deep_dive_pattern",
    "type": "parallel",
    "description": (
        "Deep analysis of a single contract: multi-tool comprehensive scan + "
        "formal verification + extended fuzzing. Best for critical contracts."
    ),
    "unified_context": True,  # Shared context for collaborative deep analysis
    "configs": [
        # Multi-tool static analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Multi-Tool Static Analysis. Use the MAIN PROMPT for target. "
                "Run ALL static analyzers: slither_analyze, mythril_analyze, "
                "securify_analyze, oyente_analyze. "
                "Aggregate results with aggregate_tool_results() and "
                "correlate with correlate_findings(). "
                "Focus on findings confirmed by multiple tools."
            ),
        ),
        # Formal verification
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Formal Verification. Use the MAIN PROMPT for target. "
                "Run certora_verify() with custom invariants if .spec files exist. "
                "Run certora_check_invariants() for standard property checks. "
                "Focus on critical invariants: balance integrity, access control, "
                "state transition validity."
            ),
        ),
        # Extended fuzzing
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Extended Fuzzing. Use the MAIN PROMPT for target. "
                "Run extended fuzzing campaign: "
                "1. echidna_fuzz with --test-limit 100000 "
                "2. echidna_coverage for coverage analysis "
                "3. medusa_fuzz with --workers 10 --timeout 600 "
                "Focus on edge cases and state explosion."
            ),
        ),
        # Economic analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Economic Analysis. Use the MAIN PROMPT for target. "
                "Run economic security analysis: "
                "1. find_economic_invariants() to identify assumptions "
                "2. analyze_contract_interactions() for external dependencies "
                "3. check_invariant_violations() with other agents' findings "
                "4. estimate_attacker_cost() for top findings "
                "Focus on flash loan vectors and oracle manipulation."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 4: Web3 DeFi Focus (Protocol-level)
# =============================================================================
web3_defi_pattern = {
    "name": "web3_defi_pattern",
    "type": "parallel",
    "description": (
        "DeFi protocol-focused audit: economic invariants + oracle analysis + "
        "flash loan vectors + governance checks. Best for DeFi protocols."
    ),
    "unified_context": False,
    "configs": [
        # Core contract analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Core Contract Security. Use the MAIN PROMPT for target. "
                "Focus on DeFi-specific vulnerabilities: "
                "- Reentrancy in deposit/withdraw/swap functions "
                "- Share/asset accounting precision (ERC4626 style) "
                "- Access control on sensitive functions "
                "- Upgradeability hazards "
                "Use slither_analyze and mythril_analyze."
            ),
        ),
        # Economic analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Economic Security. Use the MAIN PROMPT for target. "
                "Focus on economic attack vectors: "
                "- Flash loan attack feasibility "
                "- Oracle manipulation vectors "
                "- Price impact on large operations "
                "- Impermanent loss amplification "
                "- MEV/sandwich attack surfaces "
                "Use find_economic_invariants() and analyze_contract_interactions()."
            ),
        ),
        # Governance analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Governance Security. Use the MAIN PROMPT for target. "
                "Focus on governance vulnerabilities: "
                "- Flash loan governance attacks "
                "- Timelock bypass opportunities "
                "- Proposal manipulation "
                "- Quorum gaming "
                "- Admin key centralization "
                "Use slither_analyze with --detect controlled-delegatecall,arbitrary-send."
            ),
        ),
        # Integration analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Integration Security. Use the MAIN PROMPT for target. "
                "Focus on integration risks: "
                "- External protocol dependencies "
                "- Oracle trust assumptions "
                "- Cross-chain messaging (if applicable) "
                "- Token compatibility (weird ERC20s) "
                "Use analyze_contract_interactions() to map dependencies."
            ),
        ),
    ],
}


# =============================================================================
# Pattern 5: Web3 Attack Graph Builder
# =============================================================================
web3_attack_graph_pattern = {
    "name": "web3_attack_graph_pattern",
    "type": "parallel",
    "description": (
        "Game-theoretic attack graph construction: discovery + graph building + "
        "path analysis + scoring. Best for strategic prioritization."
    ),
    "unified_context": True,  # Shared for graph building
    "configs": [
        # Initial discovery
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Initial Discovery. Use the MAIN PROMPT for target. "
                "Run comprehensive discovery: "
                "1. slither_analyze with --json for structured output "
                "2. mythril_analyze with -o json "
                "3. filter_false_positives() on all findings "
                "Output findings in JSON format for graph building."
            ),
        ),
        # Attack graph construction
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Attack Graph Construction. "
                "Take findings from Discovery agent and: "
                "1. build_attack_graph() from all findings "
                "2. find_exploit_paths() to identify chains "
                "3. score_path_payoff() for each path "
                "Output: Complete attack graph with scored paths."
            ),
        ),
        # Strategic analysis
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Strategic Analysis. "
                "Take attack graph and: "
                "1. rank_findings_by_exploitability() "
                "2. estimate_attacker_cost() for top paths "
                "3. generate_strategic_digest() for final prioritization "
                "Output: Game-theoretic prioritized action plan."
            ),
        ),
    ],
}
