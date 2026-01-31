"""
Web3 Security Tools Package

This package contains integrations for various web3 security analysis tools
including static analyzers, fuzzers, symbolic executors, formal verifiers, and comprehensive auditors.

Available tools:
- Slither: Static analysis for Solidity
- Slitheryn: Enhanced Slither with AI analysis and extended detectors
- Mythril: Symbolic execution and security analysis
- Securify: Pattern-based security analysis
- Echidna: Property-based fuzzing
- Medusa: Coverage-guided fuzzing
- Fuzz-utils: Fuzzing utilities and helpers
- Gambit: Mutation testing for test suite quality
- Clorgetizer: Gas usage analysis and optimization
- Certora Prover: Formal verification with mathematical proofs
- Oyente Plus: Symbolic execution analysis
- Auditor Framework: Comprehensive auditing platform
- Scribble: Contract instrumentation for property testing
- WASP: Web3 Audit Security Platform orchestrator

Enhancement Tools (Game-Theoretic Reasoning Layer):
- Attack Graph: Build and analyze attack graphs from findings
- Cross-Contract: Analyze inter-contract interactions and invariants
- Exploit Scorer: Game-theoretic scoring of exploit viability
- Multi-Tool Orchestrator: Aggregate and correlate multi-tool findings
- Repo Context: Detect repo context and set safe defaults
"""

# Slither - Static Analysis
from .slither import (
    slither_analyze,
    slither_check_upgradeability,
    slither_detectors_list,
    slither_printers_list,
)

# Slitheryn - Enhanced Static Analysis with AI
from .slitheryn import (
    slitheryn_analyze,
    slitheryn_ai_analyze,
    slitheryn_print,
    slitheryn_list_detectors,
    slitheryn_list_printers,
    slitheryn_triage,
    slitheryn_from_etherscan,
    slitheryn_foundry,
    slitheryn_hardhat,
)

# Mythril - Symbolic Execution
from .mythril import (
    mythril_analyze,
    mythril_safe_functions,
    mythril_disassemble,
    mythril_concolic,
    mythril_foundry,
    mythril_read_storage,
    mythril_list_detectors,
    mythril_function_to_hash,
)

# Securify - Pattern-Based Analysis
from .securify import (
    securify_analyze,
    securify_from_blockchain,
    securify_list_patterns,
    securify_compliance_check,
    securify_critical_only,
    securify_with_interpreter,
    securify_visualize_ast,
)

# Echidna - Property-Based Fuzzing
from .echidna import echidna_fuzz, echidna_assertion_mode, echidna_coverage

# Medusa - Coverage-Guided Fuzzing
from .medusa import medusa_fuzz, medusa_init, medusa_test

# Fuzz Utils
from .fuzz_utils import (
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage
)

# Gambit - Mutation Testing
from .gambit import (
    gambit_mutate,
    gambit_summary,
    gambit_run_tests,
    gambit_analyze_survivors,
    # Backward compatibility aliases
    gambit_analyze,
    gambit_verify_property,
    gambit_explore_paths,
)

# Clorgetizer - Gas Analysis
from .clorgetizer import clorgetizer_analyze, clorgetizer_compare_versions, clorgetizer_optimize

# Certora Prover - Formal Verification
from .certora_prover import (
    certora_verify,
    certora_foundry,
    certora_project_sanity,
    certora_compilation_only,
    certora_with_linking,
    certora_check_invariants,
    certora_run_tests,
)

# Oyente Plus - Symbolic Execution
from .oyente_plus import (
    oyente_analyze,
    oyente_analyze_remote,
    oyente_check_vulnerability,
    oyente_generate_tests,
    oyente_with_state,
    oyente_print_paths,
    oyente_compare_contracts,
)

# Auditor Framework
from .auditor_framework import auditor_run_audit, auditor_check_compliance, auditor_generate_report, auditor_scan_dependencies

# Validation Tools
from .validate_findings import (
    validate_finding,
    filter_false_positives,
    council_filter_findings,
)

# Scribble - Contract Instrumentation
from .scribble import scribble_run

# Scribble + Mythril Integration
from .scribble_mythril import (
    scribble_instrument,
    scribble_arm,
    scribble_disarm,
    scribble_mythril_verify,
    scribble_coverage_check,
    generate_scribble_annotations,
)

# WASP - Web3 Audit Security Platform
from .wasp import (
    wasp_audit,
    wasp_quick,
    wasp_ai_analyze,
    wasp_gen_invariants,
    wasp_gen_spec,
    wasp_categories,
    wasp_tools,
    wasp_status,
    wasp_pattern_scan,
    wasp_review,
    wasp_learning_stats,
    wasp_watch,
    wasp_dashboard,
    wasp_init,
)

# Memory + RAG
from .memory_bank import web3_memory_add, web3_memory_query
from .knowledge_base import web3_kb_query, web3_kb_add, web3_rag_query
from .tooling import web3_tool_status
from .audit_planner import plan_web3_audit

# Enhancement Tools (Game-Theoretic Reasoning Layer)
from .enhancements import (
    # Attack Graph
    build_attack_graph,
    find_exploit_paths,
    score_path_payoff,
    # Cross-Contract Analysis
    analyze_contract_interactions,
    find_economic_invariants,
    check_invariant_violations,
    # Exploit Scoring
    score_exploit_viability,
    rank_findings_by_exploitability,
    estimate_attacker_cost,
    # Multi-Tool Orchestrator
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
    # Repo Context
    detect_web3_repo_context,
)

__all__ = [
    # Slither
    'slither_analyze',
    'slither_check_upgradeability',
    'slither_detectors_list',
    'slither_printers_list',
    # Slitheryn
    'slitheryn_analyze',
    'slitheryn_ai_analyze',
    'slitheryn_print',
    'slitheryn_list_detectors',
    'slitheryn_list_printers',
    'slitheryn_triage',
    'slitheryn_from_etherscan',
    'slitheryn_foundry',
    'slitheryn_hardhat',
    # Mythril
    'mythril_analyze',
    'mythril_safe_functions',
    'mythril_disassemble',
    'mythril_concolic',
    'mythril_foundry',
    'mythril_read_storage',
    'mythril_list_detectors',
    'mythril_function_to_hash',
    # Securify
    'securify_analyze',
    'securify_from_blockchain',
    'securify_list_patterns',
    'securify_compliance_check',
    'securify_critical_only',
    'securify_with_interpreter',
    'securify_visualize_ast',
    # Echidna
    'echidna_fuzz',
    'echidna_assertion_mode',
    'echidna_coverage',
    # Medusa
    'medusa_fuzz',
    'medusa_init',
    'medusa_test',
    # Fuzz Utils
    'fuzz_utils_run',
    'generate_fuzz_seeds',
    'minimize_fuzz_corpus',
    'analyze_fuzz_coverage',
    # Gambit
    'gambit_mutate',
    'gambit_summary',
    'gambit_run_tests',
    'gambit_analyze_survivors',
    # Gambit - Backward compatibility
    'gambit_analyze',
    'gambit_verify_property',
    'gambit_explore_paths',
    # Clorgetizer
    'clorgetizer_analyze',
    'clorgetizer_compare_versions',
    'clorgetizer_optimize',
    # Certora Prover
    'certora_verify',
    'certora_foundry',
    'certora_project_sanity',
    'certora_compilation_only',
    'certora_with_linking',
    'certora_check_invariants',
    'certora_run_tests',
    # Oyente Plus
    'oyente_analyze',
    'oyente_analyze_remote',
    'oyente_check_vulnerability',
    'oyente_generate_tests',
    'oyente_with_state',
    'oyente_print_paths',
    'oyente_compare_contracts',
    # Auditor Framework
    'auditor_run_audit',
    'auditor_check_compliance',
    'auditor_generate_report',
    'auditor_scan_dependencies',
    # Validation
    'validate_finding',
    'filter_false_positives',
    'council_filter_findings',
    # Scribble
    'scribble_run',
    # Scribble + Mythril Integration
    'scribble_instrument',
    'scribble_arm',
    'scribble_disarm',
    'scribble_mythril_verify',
    'scribble_coverage_check',
    'generate_scribble_annotations',
    # WASP
    'wasp_audit',
    'wasp_quick',
    'wasp_ai_analyze',
    'wasp_gen_invariants',
    'wasp_gen_spec',
    'wasp_categories',
    'wasp_tools',
    'wasp_status',
    'wasp_pattern_scan',
    'wasp_review',
    'wasp_learning_stats',
    'wasp_watch',
    'wasp_dashboard',
    'wasp_init',
    # Memory + RAG
    'web3_memory_add',
    'web3_memory_query',
    'web3_kb_query',
    'web3_kb_add',
    'web3_rag_query',
    # Tooling + Workflow
    'web3_tool_status',
    'plan_web3_audit',
    # Enhancement Tools - Attack Graph
    'build_attack_graph',
    'find_exploit_paths',
    'score_path_payoff',
    # Enhancement Tools - Cross-Contract Analysis
    'analyze_contract_interactions',
    'find_economic_invariants',
    'check_invariant_violations',
    # Enhancement Tools - Exploit Scoring
    'score_exploit_viability',
    'rank_findings_by_exploitability',
    'estimate_attacker_cost',
    # Enhancement Tools - Multi-Tool Orchestrator
    'aggregate_tool_results',
    'correlate_findings',
    'generate_strategic_digest',
    # Enhancement Tools - Repo Context
    'detect_web3_repo_context',
]
