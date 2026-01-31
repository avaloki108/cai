"""
Web3 Bug Bounty Agent

A specialized agent for comprehensive Web3 security auditing with game-theoretic
prioritization. Combines existing security tools (Slither, Mythril, etc.) with
custom enhancement tools for attack graph construction, exploit chain discovery,
and strategic prioritization.

Architecture:
- Existing tools = Sensors (Slither, Slitheryn, Mythril, etc.)
- Enhancement tools = Reasoning layer (attack graphs, scoring, orchestration)
- Game-theoretic approach = Payoff/effort prioritization

Tiered Attack Surface:
- Tier 1: Contract + Protocol Logic (highest ROI)
- Tier 2: Economic + Oracle + Integration
- Tier 3: Frontend + Infrastructure
"""

import os
from dotenv import load_dotenv
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from cai.util import load_prompt_template, create_system_prompt_renderer

# === General Tools ===
from cai.tools.reconnaissance.generic_linux_command import (
    generic_linux_command
)
from cai.tools.reconnaissance.filesystem import (
    list_dir,
    cat_file,
    eza_list,
    less_file,
    change_directory,
    pwd_command,
    find_file,
    read_file_lines,
)
from cai.tools.web.search_web import (
    make_google_search
)
from cai.tools.reconnaissance.exec_code import (
    execute_code
)
from cai.tools.reconnaissance.shodan import (
    shodan_search,
    shodan_host_info
)

# === Existing Web3 Security Tools (Sensors) ===
from cai.tools.web3_security import (
    # Slither - Static Analysis
    slither_analyze,
    slither_check_upgradeability,
    slither_detectors_list,
    slither_printers_list,
    # Slitheryn - Enhanced Static Analysis with AI
    slitheryn_analyze,
    slitheryn_ai_analyze,
    slitheryn_print,
    slitheryn_list_detectors,
    slitheryn_list_printers,
    slitheryn_triage,
    slitheryn_from_etherscan,
    slitheryn_foundry,
    slitheryn_hardhat,
    # Mythril - Symbolic Execution
    mythril_analyze,
    mythril_safe_functions,
    mythril_disassemble,
    mythril_concolic,
    mythril_foundry,
    mythril_read_storage,
    mythril_list_detectors,
    mythril_function_to_hash,
    # Securify - Pattern-Based Analysis
    securify_analyze,
    securify_from_blockchain,
    securify_list_patterns,
    securify_compliance_check,
    securify_critical_only,
    securify_with_interpreter,
    securify_visualize_ast,
    # Echidna - Property-based Fuzzing
    echidna_fuzz,
    echidna_assertion_mode,
    echidna_coverage,
    # Medusa - Coverage-guided Fuzzing
    medusa_fuzz,
    medusa_init,
    medusa_test,
    # Fuzz Utils
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage,
    # Gambit - Mutation Testing
    gambit_mutate,
    gambit_summary,
    gambit_run_tests,
    gambit_analyze_survivors,
    # Clorgetizer - Gas Analysis
    clorgetizer_analyze,
    clorgetizer_compare_versions,
    clorgetizer_optimize,
    # Certora - Formal Verification
    certora_verify,
    certora_foundry,
    certora_project_sanity,
    certora_compilation_only,
    certora_with_linking,
    certora_check_invariants,
    certora_run_tests,
    # Oyente Plus - Symbolic Execution
    oyente_analyze,
    oyente_analyze_remote,
    oyente_check_vulnerability,
    oyente_generate_tests,
    oyente_with_state,
    oyente_print_paths,
    oyente_compare_contracts,
    # Auditor Framework
    auditor_run_audit,
    auditor_check_compliance,
    auditor_generate_report,
    auditor_scan_dependencies,
    # Validation Tools (CRITICAL for false positive filtering)
    validate_finding,
    filter_false_positives,
    council_filter_findings,
    # Scribble - Instrumentation
    scribble_run,
    # Scribble + Mythril - Property-Based Verification
    scribble_instrument,
    scribble_arm,
    scribble_disarm,
    scribble_mythril_verify,
    scribble_coverage_check,
    generate_scribble_annotations,
    # WASP - Web3 Audit Security Platform
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
    # Memory + RAG
    web3_memory_add,
    web3_memory_query,
    web3_kb_query,
    web3_kb_add,
    web3_rag_query,
    # Tooling + Workflow
    web3_tool_status,
    plan_web3_audit,
)

# === Custom Enhancement Tools (Reasoning Layer) ===
from cai.tools.web3_security.enhancements import (
    # Attack Graph Construction
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
    # Multi-Tool Orchestration
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
    # Repo Context
    detect_web3_repo_context,
)

from cai.agents.guardrails import get_security_guardrails

load_dotenv()

# API key configuration - allow non-OpenAI providers
api_key = (
    os.getenv("ALIAS_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("MISTRAL_API_KEY")
    or os.getenv("MISTRALAI_API_KEY")
    or os.getenv("ZAI_API_KEY")
)
if not api_key:
    raise RuntimeError(
        "Web3 Bug Bounty Agent requires an API key. "
        "Set ALIAS_API_KEY, OPENAI_API_KEY, MISTRAL_API_KEY, or ZAI_API_KEY."
    )

# Load specialized Web3 bug bounty prompt
web3_bug_bounty_system_prompt = load_prompt_template("prompts/system_web3_bug_bounty.md")

# === Tool List ===
# Organized by category for clarity

# Core general purpose tools (always included)
general_tools = [
    execute_code,
    # File system exploration tools
    list_dir,
    cat_file,
    eza_list,
    less_file,
    change_directory,
    pwd_command,
    find_file,
    read_file_lines,
]

# Tier 3: Infrastructure reconnaissance tools
# Always include generic_linux_command for file system exploration (ls, cat, find, etc.)
# This is essential for understanding project structure before running security tools
tier3_infra_tools = [
    generic_linux_command,  # Always available for file system exploration
]
# Add other infra tools (Shodan) only if explicitly enabled
if os.getenv("WEB3_ENABLE_INFRA_TOOLS", "false").lower() == "true":
    tier3_infra_tools.extend([
        shodan_search,
        shodan_host_info,
    ])

# Static analysis sensors (Slither + Slitheryn)
static_analysis_tools = [
    # Slither
    slither_analyze,
    slither_check_upgradeability,
    slither_detectors_list,
    slither_printers_list,
    # Slitheryn (Enhanced)
    slitheryn_analyze,
    slitheryn_ai_analyze,
    slitheryn_print,
    slitheryn_list_detectors,
    slitheryn_list_printers,
    slitheryn_triage,
    slitheryn_from_etherscan,
    slitheryn_foundry,
    slitheryn_hardhat,
    # Securify
    securify_analyze,
    securify_from_blockchain,
    securify_list_patterns,
    securify_compliance_check,
    securify_critical_only,
    securify_with_interpreter,
    securify_visualize_ast,
]

# Symbolic execution sensors (Mythril, Oyente)
symbolic_execution_tools = [
    # Mythril
    mythril_analyze,
    mythril_safe_functions,
    mythril_disassemble,
    mythril_concolic,
    mythril_foundry,
    mythril_read_storage,
    mythril_list_detectors,
    mythril_function_to_hash,
    # Oyente Plus
    oyente_analyze,
    oyente_analyze_remote,
    oyente_check_vulnerability,
    oyente_generate_tests,
    oyente_with_state,
    oyente_print_paths,
    oyente_compare_contracts,
]

# Fuzzing sensors
fuzzing_tools = [
    echidna_fuzz,
    echidna_assertion_mode,
    echidna_coverage,
    medusa_fuzz,
    medusa_init,
    medusa_test,
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage,
]

# Mutation testing tools (Gambit)
mutation_testing_tools = [
    gambit_mutate,
    gambit_summary,
    gambit_run_tests,
    gambit_analyze_survivors,
]

# Formal verification tools (Certora)
formal_verification_tools = [
    certora_verify,
    certora_foundry,
    certora_project_sanity,
    certora_compilation_only,
    certora_with_linking,
    certora_check_invariants,
    certora_run_tests,
]

# Gas and optimization tools
optimization_tools = [
    clorgetizer_analyze,
    clorgetizer_compare_versions,
    clorgetizer_optimize,
]

# Comprehensive audit tools
audit_tools = [
    auditor_run_audit,
    auditor_check_compliance,
    auditor_generate_report,
    auditor_scan_dependencies,
    scribble_run,
]

# Scribble + Mythril property-based verification tools
property_verification_tools = [
    scribble_instrument,
    scribble_arm,
    scribble_disarm,
    scribble_mythril_verify,
    scribble_coverage_check,
    generate_scribble_annotations,
]

# WASP - Web3 Audit Security Platform (Orchestrator)
wasp_platform_tools = [
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
]

# Validation tools (CRITICAL for reducing false positives)
validation_tools = [
    validate_finding,
    filter_false_positives,
    council_filter_findings,
]

# Memory bank tools
memory_tools = [
    web3_memory_add,
    web3_memory_query,
]

# RAG knowledge base tools
rag_tools = [
    web3_kb_query,
    web3_kb_add,
    web3_rag_query,
]

# Workflow and tooling utilities
workflow_tools = [
    web3_tool_status,
    plan_web3_audit,
]

# Game-theoretic enhancement tools (reasoning layer)
enhancement_tools = [
    # Attack graph construction
    build_attack_graph,
    find_exploit_paths,
    score_path_payoff,
    # Cross-contract analysis
    analyze_contract_interactions,
    find_economic_invariants,
    check_invariant_violations,
    # Exploit scoring
    score_exploit_viability,
    rank_findings_by_exploitability,
    estimate_attacker_cost,
    # Multi-tool orchestration
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
    # Repo context
    detect_web3_repo_context,
]

# Combine all tools
tools = (
    general_tools +
    static_analysis_tools +
    symbolic_execution_tools +
    fuzzing_tools +
    mutation_testing_tools +
    formal_verification_tools +
    optimization_tools +
    audit_tools +
    property_verification_tools +
    wasp_platform_tools +
    validation_tools +
    memory_tools +
    rag_tools +
    workflow_tools +
    enhancement_tools +
    tier3_infra_tools  # Only included if WEB3_ENABLE_INFRA_TOOLS=true
)

# Conditionally add Google search if configured
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    tools.append(make_google_search)

# Get security guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# === Agent Definition ===
web3_bug_bounty_agent = Agent(
    name="Web3 Bug Bounty Hunter",
    instructions=create_system_prompt_renderer(web3_bug_bounty_system_prompt),
    description="""Specialized Web3 security auditing agent with game-theoretic prioritization.
    
    Comprehensive Tool Suite:
    - Static Analysis: Slither, Slitheryn (with AI), Securify
    - Symbolic Execution: Mythril (analyze, concolic, foundry), Oyente Plus
    - Fuzzing: Echidna, Medusa, Fuzz-utils
    - Mutation Testing: Gambit (mutate, summary, analyze survivors)
    - Formal Verification: Certora Prover (verify, invariants, linking)
    - Property Testing: Scribble + Mythril integration
    - Orchestration: WASP (audit, gen-invariants, gen-spec, pattern-scan)
    
    Key Capabilities:
    - Attack graph construction and exploit path discovery
    - Game-theoretic payoff/effort scoring for finding prioritization
    - Cross-contract interaction analysis
    - Economic invariant identification
    - Multi-tool result aggregation and correlation
    - Strategic digest generation for decision-making
    
    Tiered Approach:
    - Tier 1: Contract + Protocol Logic (highest ROI)
    - Tier 2: Economic + Oracle + Integration
    - Tier 3: Frontend + Infrastructure
    
    Key Differentiator: Prioritizes findings by exploitability (payoff/effort),
    not just severity. Focuses on real, permissionless, economically viable exploits.""",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)
