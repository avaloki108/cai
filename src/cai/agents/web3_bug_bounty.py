"""
Web3 Bug Bounty Agent

Focused Web3 security auditing agent. Trimmed toolset for maximum context
efficiency — 23 tools instead of 130+ = ~76K tokens recovered for actual code.

Tool Philosophy: A real bounty hunter needs shell access, slither, mythril,
echidna, medusa, scribble, and a few specialized analyzers. Everything else
is either redundant, abandoned, or LLM reasoning that belongs in the prompt.

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
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.filesystem import (
    cat_file,
    less_file,
    pwd_command,
    read_file_lines,
)
from cai.tools.web.search_web import make_google_search
from cai.tools.reconnaissance.exec_code import execute_code

# === Web3 Security Tools (trimmed — see TOOL_TRIM_PLAN.md for rationale) ===
from cai.tools.web3_security import (
    # Slither — static analysis workhorse
    slither_analyze,
    slither_detectors_list,
    slither_check_upgradeability,
    # Mythril — symbolic execution
    mythril_analyze,
    # Echidna — property-based fuzzing
    echidna_fuzz,
    # Medusa — coverage-guided fuzzing
    medusa_fuzz,
    # Scribble — property instrumentation
    scribble_run,
    # Validation
    validate_finding,
)

# === Web3 Plugin Runner (Cursor-added) ===
from cai.tools.web3_security.runner import (
    list_web3_plugins,
    describe_web3_plugin,
    run_web3_plugin,
)

# === Enhancement Tools (recon + bridge only — reasoning is in the prompt) ===
from cai.tools.web3_security.enhancements import (
    detect_web3_repo_context,
    discover_proxy_patterns,
)

from cai.agents.guardrails import get_security_guardrails
from cai.agents.bridge_analyzer import (
    check_known_bridge_exploits,
)

load_dotenv()

# API key configuration - allow non-OpenAI providers
api_key = (
    os.getenv("ALIAS_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("MISTRAL_API_KEY")
    or os.getenv("MISTRALAI_API_KEY")
    or os.getenv("ZAI_API_KEY")
    or os.getenv("ANTHROPIC_API_KEY")
)

# If no API key is set, use a placeholder to prevent hanging
# The error will be raised when the agent tries to actually use the key
if not api_key:
    api_key = "sk-placeholder-no-valid-key"
    print(
        "\n⚠️  WARNING: No API key configured!\n"
        "Web3 Bug Bounty Hunter requires one of:\n"
        "  - ALIAS_API_KEY\n"
        "  - OPENAI_API_KEY\n"
        "  - MISTRAL_API_KEY / MISTRALAI_API_KEY\n"
        "  - ZAI_API_KEY\n"
        "  - ANTHROPIC_API_KEY\n\n"
        "Set any of these environment variables to enable the agent.\n"
    )

# Load specialized Web3 bug bounty prompt
web3_bug_bounty_system_prompt = load_prompt_template("prompts/system_web3_bug_bounty.md")

# === Tool List (TRIMMED) ===
# Only essential tools — each tool schema costs ~700 tokens in context.
# Full audit in TOOL_TRIM_PLAN.md. 130 -> 20 tools = ~76K tokens recovered.

# Core tools: shell, targeted filesystem reads, code execution
general_tools = [
    generic_linux_command,  # Shell access — run anything
    execute_code,           # Python scripts, PoCs, math verification
    cat_file,               # Read target source
    less_file,              # Paginated reading for large files
    read_file_lines,        # Targeted line reading
    pwd_command,            # Know where you are
]

# Static analysis — the workhorses
static_analysis_tools = [
    slither_analyze,           # Core static analysis
    slither_detectors_list,    # Know available detectors
    slither_check_upgradeability,  # Proxy/upgrade safety
]

# Symbolic execution
symbolic_execution_tools = [
    mythril_analyze,       # Symbolic execution, complementary to slither
]

# Fuzzing
fuzzing_tools = [
    echidna_fuzz,   # Property-based fuzzing
    medusa_fuzz,    # Corpus-based fuzzing
]

# Property verification
verification_tools = [
    scribble_run,   # Instrument code for fuzzing
]

# Recon & context detection
recon_tools = [
    detect_web3_repo_context,  # Auto-detect framework, proxies, architecture
    discover_proxy_patterns,   # Find proxy/implementation splits
]

# Validation
validation_tools = [
    validate_finding,  # Check if a finding is real vs false positive
    list_web3_plugins,  # Enumerate runner-exposed Web3 plugins
    describe_web3_plugin,  # Inspect plugin schemas/metadata
    run_web3_plugin,  # Execute plugins via policy-governed runner
]

# Bridge-specific analysis (useful for bridge targets)
bridge_tools = [
    check_known_bridge_exploits,        # Pattern-match known bridge vulns
]

# Conditional: add Google search if configured
optional_tools = []
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    optional_tools.append(make_google_search)

# Combine all tools
tools = (
    general_tools +
    static_analysis_tools +
    symbolic_execution_tools +
    fuzzing_tools +
    verification_tools +
    recon_tools +
    validation_tools +
    bridge_tools +
    optional_tools
)

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
    - Bridge/Cross-Chain: replay protection, signature verification, message validation,
      validator security, known bridge exploits (Ronin, Wormhole, Nomad, Harmony), audit report
    
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
