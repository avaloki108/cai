"""
Web3 Security Tools Package

This package contains integrations for various web3 security analysis tools
including static analyzers, fuzzers, symbolic executors, formal verifiers, and comprehensive auditors.

Available tools:
- Slither: Static analysis for Solidity
- Mythril: Symbolic execution and security analysis
- Securify: Formal verification and compliance checking
- Echidna: Property-based fuzzing
- Medusa: Coverage-guided fuzzing
- Fuzz-utils: Fuzzing utilities and helpers
- Gambit: Symbolic execution for vulnerability detection
- Clorgetizer: Gas usage analysis and optimization
- Certora Prover: Formal verification with mathematical proofs
- Oyente Plus: Enhanced symbolic execution analysis
- Auditor Framework: Comprehensive auditing platform

Enhancement Tools (Game-Theoretic Reasoning Layer):
- Attack Graph: Build and analyze attack graphs from findings
- Cross-Contract: Analyze inter-contract interactions and invariants
- Exploit Scorer: Game-theoretic scoring of exploit viability
- Multi-Tool Orchestrator: Aggregate and correlate multi-tool findings
"""

from .slither import slither_analyze, slither_check_upgradeability
from .mythril import mythril_analyze, mythril_disassemble, mythril_read_storage
from .securify import securify_analyze, securify_compliance_check
from .echidna import echidna_fuzz, echidna_assertion_mode, echidna_coverage
from .medusa import medusa_fuzz, medusa_init, medusa_test
from .fuzz_utils import (
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage
)
from .gambit import gambit_analyze, gambit_verify_property, gambit_explore_paths
from .clorgetizer import clorgetizer_analyze, clorgetizer_compare_versions, clorgetizer_optimize
from .certora_prover import certora_verify, certora_run_tests, certora_check_invariants
from .oyente_plus import oyente_analyze, oyente_check_vulnerability, oyente_compare_contracts
from .auditor_framework import auditor_run_audit, auditor_check_compliance, auditor_generate_report, auditor_scan_dependencies
from .validate_findings import validate_finding, filter_false_positives
from .scribble import scribble_run

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
)

__all__ = [
    # Slither
    'slither_analyze',
    'slither_check_upgradeability',
    # Mythril
    'mythril_analyze',
    'mythril_disassemble',
    'mythril_read_storage',
    # Securify
    'securify_analyze',
    'securify_compliance_check',
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
    'gambit_analyze',
    'gambit_verify_property',
    'gambit_explore_paths',
    # Clorgetizer
    'clorgetizer_analyze',
    'clorgetizer_compare_versions',
    'clorgetizer_optimize',
    # Certora Prover
    'certora_verify',
    'certora_run_tests',
    'certora_check_invariants',
    # Oyente Plus
    'oyente_analyze',
    'oyente_check_vulnerability',
    'oyente_compare_contracts',
    # Auditor Framework
    'auditor_run_audit',
    'auditor_check_compliance',
    'auditor_generate_report',
    'auditor_scan_dependencies',
    # Validation
    'validate_finding',
    'filter_false_positives',
    # Scribble
    'scribble_run',
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
]
