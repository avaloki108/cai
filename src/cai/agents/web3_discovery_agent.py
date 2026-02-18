"""
Web3 Discovery Agent - Sensors-Only Static & Symbolic Analysis

A pure sensor agent that runs security analysis tools (Slither, Mythril,
Securify, etc.) and outputs structured findings. Does NOT score, rank,
or judge exploitability — that is the G-CTR agent's job.

This agent is designed to be used standalone or as Phase 1 in a
sequential audit pipeline:

    Discovery Agent → G-CTR Agent → Validator → Reporter

Architecture:
- Static analysis sensors (Slither, Slitheryn, Securify)
- Symbolic execution sensors (Mythril, Oyente)
- Coverage mapping (Echidna coverage mode)
- False positive pre-filtering
- Structured DISCOVERY_FINDINGS_JSON output
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
from cai.tools.reconnaissance.exec_code import (
    execute_code
)

# === Static Analysis Sensors ===
from cai.tools.web3_security import (
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
)

# === Symbolic Execution Sensors ===
from cai.tools.web3_security import (
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
)

# === Coverage Sensors (not full fuzzing) ===
from cai.tools.web3_security import (
    echidna_coverage,
)

# === Validation Tools (pre-filter obvious FPs) ===
from cai.tools.web3_security import (
    validate_finding,
    filter_false_positives,
)

# === Repo Context ===
from cai.tools.web3_security.enhancements import (
    detect_web3_repo_context,
)

# === Workflow ===
from cai.tools.web3_security import (
    web3_tool_status,
)

from cai.agents.guardrails import get_security_guardrails

load_dotenv()

# API key configuration
api_key = (
    os.getenv("ALIAS_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("MISTRAL_API_KEY")
    or os.getenv("MISTRALAI_API_KEY")
    or os.getenv("ZAI_API_KEY")
)
if not api_key:
    raise RuntimeError(
        "Web3 Discovery Agent requires an API key. "
        "Set ALIAS_API_KEY, OPENAI_API_KEY, MISTRAL_API_KEY, or ZAI_API_KEY."
    )

# Load specialized Discovery prompt
web3_discovery_system_prompt = load_prompt_template(
    "prompts/system_web3_discovery.md"
)

# === Tool List ===
# Organized: general → static → symbolic → coverage → validation → context

general_tools = [
    execute_code,
    list_dir,
    cat_file,
    eza_list,
    less_file,
    change_directory,
    pwd_command,
    find_file,
    read_file_lines,
    generic_linux_command,
]

static_analysis_tools = [
    # Slither
    slither_analyze,
    slither_check_upgradeability,
    slither_detectors_list,
    slither_printers_list,
    # Slitheryn
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

coverage_tools = [
    echidna_coverage,
]

validation_tools = [
    validate_finding,
    filter_false_positives,
]

context_tools = [
    detect_web3_repo_context,
    web3_tool_status,
]

# Combine all tools
tools = (
    general_tools
    + static_analysis_tools
    + symbolic_execution_tools
    + coverage_tools
    + validation_tools
    + context_tools
)

# Get security guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# === Agent Definition ===
web3_discovery_agent = Agent(
    name="Web3 Discovery Agent",
    instructions=create_system_prompt_renderer(web3_discovery_system_prompt),
    description="""Sensors-only Web3 security agent. Runs static analysis (Slither,
    Slitheryn, Securify), symbolic execution (Mythril, Oyente), and coverage mapping
    (Echidna). Outputs structured DISCOVERY_FINDINGS_JSON for the G-CTR agent.

    Does NOT score, rank, or judge exploitability. Pure sensor array.

    Use standalone for quick scans or as Phase 1 in:
    Discovery Agent → G-CTR Agent → Validator → Reporter""",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)
