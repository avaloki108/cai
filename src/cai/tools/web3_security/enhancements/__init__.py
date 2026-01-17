"""
Web3 Security Enhancement Tools

This package provides game-theoretic reasoning and orchestration capabilities
on top of existing web3 security sensors (Slither, Mythril, etc.).

The philosophy is:
- Existing tools = Sensors (raw signal detection)
- Enhancement tools = Reasoning layer (prioritization, correlation, exploit chains)

Available modules:
- attack_graph: Build and analyze attack graphs from vulnerability findings
- cross_contract: Analyze inter-contract interactions and economic invariants
- exploit_scorer: Game-theoretic scoring of exploit viability
- multi_tool_orchestrator: Aggregate and correlate findings from multiple tools
- repo_context: Detect repo context and set safe defaults
"""

from .attack_graph import (
    build_attack_graph,
    find_exploit_paths,
    score_path_payoff,
)

from .cross_contract import (
    analyze_contract_interactions,
    find_economic_invariants,
    check_invariant_violations,
)

from .exploit_scorer import (
    score_exploit_viability,
    rank_findings_by_exploitability,
    estimate_attacker_cost,
)

from .multi_tool_orchestrator import (
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
)

from .repo_context import (
    detect_web3_repo_context,
)

__all__ = [
    # Attack Graph
    'build_attack_graph',
    'find_exploit_paths',
    'score_path_payoff',
    # Cross-Contract
    'analyze_contract_interactions',
    'find_economic_invariants',
    'check_invariant_violations',
    # Exploit Scorer
    'score_exploit_viability',
    'rank_findings_by_exploitability',
    'estimate_attacker_cost',
    # Multi-Tool Orchestrator
    'aggregate_tool_results',
    'correlate_findings',
    'generate_strategic_digest',
    # Repo Context
    'detect_web3_repo_context',
]

