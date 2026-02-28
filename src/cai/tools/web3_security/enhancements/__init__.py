"""
Web3 Security Enhancement Tools

Reasoning layer on top of CAI security sensors (Slither, Mythril, etc.).

Philosophy:
    Sensors  = raw signal detection  (static analyzers, fuzzers)
    Enhancements = reasoning layer   (prioritization, correlation, exploit chains)

Stage mapping  (aligns with EliteWeb3Pipeline stages):

    STAGE 0 — PRE-FLIGHT / CONTEXT
        detect_web3_repo_context        — repo auto-detection

    STAGE 1 — DISCOVERY / STATIC ANALYSIS
        iris_*                          — neuro-symbolic Slither augmentation
        discover_proxy_patterns         — proxy pattern detection
        check_initialization_state      — init-gap analysis
        construct_role_lattice          — access-control mapping
        detect_privilege_escalation     — priv-esc path detection
        validate_domain_separator       — EIP-712 domain checks
        analyze_nonce_replay            — sig replay detection
        analyze_permit_flows            — ERC-2612 permit analysis
        detect_sandwich_vulnerability   — MEV sandwich detection
        detect_frontrun_vulnerability   — frontrun detection
        detect_backrun_opportunity      — backrun detection
        detect_jit_liquidity_risk       — JIT liquidity detection

    STAGE 2 — RISK PRIORITIZATION / SCORING
        score_exploit_viability         — game-theoretic viability score
        rank_findings_by_exploitability — batch ranking
        estimate_attacker_cost          — cost estimation
        analyze_finding_feasibility     — feasibility gate

    STAGE 3 — CORRELATION / EXPLOIT CHAIN
        build_attack_graph              — attack graph construction
        find_exploit_paths              — path enumeration
        score_path_payoff               — path payoff scoring
        analyze_contract_interactions   — cross-contract flow mapping
        find_economic_invariants        — invariant extraction
        check_invariant_violations      — invariant breach detection

    STAGE 4 — AGGREGATION / STRATEGIC DIGEST
        aggregate_tool_results          — multi-tool result merge
        correlate_findings              — dedup + correlation
        generate_strategic_digest       — G-CTR-style strategic output

    STAGE 5 — MEV SIMULATION (optional)
        simulate_sandwich_attack        — sandwich PoC
        calculate_mev_exposure          — quantified MEV exposure
        suggest_mev_mitigations         — actionable mitigations
"""

# ── Stage 0: Pre-flight / Context ─────────────────────────────────────
from .repo_context import (
    detect_web3_repo_context,
)

# ── Stage 1: Discovery / Static Analysis ──────────────────────────────
from .upgradeability import (
    discover_proxy_patterns,
    check_initialization_state,
)

from .access_control import (
    construct_role_lattice,
    detect_privilege_escalation,
)

from .signatures import (
    validate_domain_separator,
    analyze_nonce_replay,
    analyze_permit_flows,
)

from .iris import (
    iris_infer_taint_specs,
    iris_contextual_filter,
    iris_enhanced_slither_analysis,
    iris_generate_custom_detector,
    iris_batch_contextual_filter,
)

# ── Stage 2: Risk Prioritization / Scoring ────────────────────────────
from .exploit_scorer import (
    score_exploit_viability,
    rank_findings_by_exploitability,
    estimate_attacker_cost,
    analyze_finding_feasibility,
)

# ── Stage 3: Correlation / Exploit Chain ──────────────────────────────
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

# ── Stage 4: Aggregation / Strategic Digest ───────────────────────────
from .multi_tool_orchestrator import (
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
)

# ── Stage 5: MEV Simulation (optional) ────────────────────────────────
try:
    from .mev_simulator import (
        detect_sandwich_vulnerability,
        detect_frontrun_vulnerability,
        detect_backrun_opportunity,
        detect_jit_liquidity_risk,
        simulate_sandwich_attack,
        calculate_mev_exposure,
        suggest_mev_mitigations,
    )
    MEV_AVAILABLE = True
except ImportError:
    MEV_AVAILABLE = False

# ── Public API ────────────────────────────────────────────────────────
__all__ = [
    # Stage 0 — Pre-flight
    'detect_web3_repo_context',
    # Stage 1 — Discovery
    'discover_proxy_patterns',
    'check_initialization_state',
    'construct_role_lattice',
    'detect_privilege_escalation',
    'validate_domain_separator',
    'analyze_nonce_replay',
    'analyze_permit_flows',
    'iris_infer_taint_specs',
    'iris_contextual_filter',
    'iris_enhanced_slither_analysis',
    'iris_generate_custom_detector',
    'iris_batch_contextual_filter',
    # Stage 2 — Scoring
    'score_exploit_viability',
    'rank_findings_by_exploitability',
    'estimate_attacker_cost',
    'analyze_finding_feasibility',
    # Stage 3 — Correlation
    'build_attack_graph',
    'find_exploit_paths',
    'score_path_payoff',
    'analyze_contract_interactions',
    'find_economic_invariants',
    'check_invariant_violations',
    # Stage 4 — Aggregation
    'aggregate_tool_results',
    'correlate_findings',
    'generate_strategic_digest',
]

if MEV_AVAILABLE:
    __all__.extend([
        'detect_sandwich_vulnerability',
        'detect_frontrun_vulnerability',
        'detect_backrun_opportunity',
        'detect_jit_liquidity_risk',
        'simulate_sandwich_attack',
        'calculate_mev_exposure',
        'suggest_mev_mitigations',
    ])
