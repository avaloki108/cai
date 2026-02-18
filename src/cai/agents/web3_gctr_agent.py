"""
Web3 G-CTR Agent - Game-Theoretic Correlation and Reasoning Core

Takes raw findings from the Discovery Agent and applies game-theoretic
reasoning to produce prioritized, exploit-viable hypotheses with attack
graphs and payoff scoring.

This agent is designed to be used standalone or as Phase 2 in a
sequential audit pipeline:

    Discovery Agent → G-CTR Agent → Validator → Reporter

Architecture:
- Finding aggregation and deduplication
- Cross-tool correlation (multi-tool confirmation = higher signal)
- Attack graph construction and exploit path discovery
- Game-theoretic payoff/effort scoring
- Strategic digest generation
- CANDIDATES_JSON output for Judge Gate pipeline

Input: DISCOVERY_FINDINGS_JSON from the Discovery Agent
Output: GCTR_DIGEST_JSON + optional CANDIDATES_JSON
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
    cat_file,
    list_dir,
    find_file,
    read_file_lines,
    change_directory,
    pwd_command,
)
from cai.tools.reconnaissance.exec_code import (
    execute_code
)

# === Game-Theoretic Enhancement Tools (Reasoning Layer) ===
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

# === Validation Tools ===
from cai.tools.web3_security import (
    validate_finding,
    filter_false_positives,
)

# === Memory + RAG ===
from cai.tools.web3_security import (
    web3_memory_add,
    web3_memory_query,
    web3_kb_query,
    web3_kb_add,
    web3_rag_query,
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
        "Web3 G-CTR Agent requires an API key. "
        "Set ALIAS_API_KEY, OPENAI_API_KEY, MISTRAL_API_KEY, or ZAI_API_KEY."
    )

# Load specialized G-CTR prompt
web3_gctr_system_prompt = load_prompt_template(
    "prompts/system_web3_gctr.md"
)

# === Tool List ===
# Organized: general → reasoning → analysis → validation → memory

general_tools = [
    generic_linux_command,
    execute_code,
    cat_file,
    list_dir,
    find_file,
    read_file_lines,
    change_directory,
    pwd_command,
]

# The core reasoning toolset - attack graphs, scoring, correlation
reasoning_tools = [
    # Attack graph construction
    build_attack_graph,
    find_exploit_paths,
    score_path_payoff,
    # Exploit scoring
    score_exploit_viability,
    rank_findings_by_exploitability,
    estimate_attacker_cost,
    # Multi-tool orchestration
    aggregate_tool_results,
    correlate_findings,
    generate_strategic_digest,
]

# Cross-contract and economic analysis
analysis_tools = [
    analyze_contract_interactions,
    find_economic_invariants,
    check_invariant_violations,
    detect_web3_repo_context,
]

# Validation (for quick checks, not full retesting)
validation_tools = [
    validate_finding,
    filter_false_positives,
]

# Memory and knowledge base
memory_tools = [
    web3_memory_add,
    web3_memory_query,
    web3_kb_query,
    web3_kb_add,
    web3_rag_query,
]

# Combine all tools
tools = (
    general_tools
    + reasoning_tools
    + analysis_tools
    + validation_tools
    + memory_tools
)

# Get security guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# === Agent Definition ===
web3_gctr_agent = Agent(
    name="Web3 G-CTR Agent",
    instructions=create_system_prompt_renderer(web3_gctr_system_prompt),
    description="""Game-Theoretic Correlation and Reasoning core for Web3 audits.
    Takes raw findings from the Discovery Agent and produces prioritized exploit
    hypotheses with attack graphs and payoff/effort scoring.

    Key Capabilities:
    - Finding aggregation, deduplication, and cross-tool correlation
    - Attack graph construction and exploit path discovery
    - Game-theoretic payoff/effort scoring (Exploit_Score formula)
    - Strategic digest generation for downstream agents
    - CANDIDATES_JSON output for Judge Gate pipeline

    Use standalone to analyze findings or as Phase 2 in:
    Discovery Agent → G-CTR Agent → Validator → Reporter""",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)
