"""
Web3 Bug Bounty Agent

A specialized agent for comprehensive Web3 security auditing with game-theoretic
prioritization. Combines existing security tools (Slither, Mythril, etc.) with
custom enhancement tools for attack graph construction, exploit chain discovery,
and strategic prioritization.

Architecture:
- Existing tools = Sensors (Slither, Mythril, Echidna, etc.)
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
    # Mythril - Symbolic Execution
    mythril_analyze,
    mythril_disassemble,
    mythril_read_storage,
    # Securify - Formal Verification
    securify_analyze,
    securify_compliance_check,
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
    # Gambit - Symbolic Execution
    gambit_analyze,
    gambit_verify_property,
    gambit_explore_paths,
    # Clorgetizer - Gas Analysis
    clorgetizer_analyze,
    clorgetizer_compare_versions,
    clorgetizer_optimize,
    # Certora - Formal Verification
    certora_verify,
    certora_run_tests,
    certora_check_invariants,
    # Oyente Plus - Legacy Symbolic
    oyente_analyze,
    oyente_check_vulnerability,
    oyente_compare_contracts,
    # Auditor Framework
    auditor_run_audit,
    auditor_check_compliance,
    auditor_generate_report,
    auditor_scan_dependencies,
    # Validation Tools (CRITICAL for false positive filtering)
    validate_finding,
    filter_false_positives,
    # Scribble - Instrumentation
    scribble_run,
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
]

# Tier 3: Infrastructure reconnaissance tools
# These expand scope into infra recon - gate behind explicit opt-in
# Set WEB3_ENABLE_INFRA_TOOLS=true to enable Shodan + generic shell
tier3_infra_tools = []
if os.getenv("WEB3_ENABLE_INFRA_TOOLS", "false").lower() == "true":
    tier3_infra_tools = [
        generic_linux_command,
        shodan_search,
        shodan_host_info,
    ]

# Static analysis sensors
static_analysis_tools = [
    slither_analyze,
    slither_check_upgradeability,
    securify_analyze,
    securify_compliance_check,
]

# Symbolic execution sensors
symbolic_execution_tools = [
    mythril_analyze,
    mythril_disassemble,
    mythril_read_storage,
    gambit_analyze,
    gambit_verify_property,
    gambit_explore_paths,
    oyente_analyze,
    oyente_check_vulnerability,
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

# Formal verification tools
formal_verification_tools = [
    certora_verify,
    certora_run_tests,
    certora_check_invariants,
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

# Validation tools (CRITICAL for reducing false positives)
validation_tools = [
    validate_finding,
    filter_false_positives,
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
    formal_verification_tools +
    optimization_tools +
    audit_tools +
    validation_tools +
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
    
    Capabilities:
    - Comprehensive smart contract analysis (static, symbolic, fuzzing, formal)
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
    not just severity. Focuses on real, economically viable exploits.""",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)
