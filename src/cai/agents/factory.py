"""
Generic agent factory module for creating agent instances dynamically.
"""

import importlib
import os
from pathlib import Path
from typing import Callable, Dict

from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.sdk.agents.logger import logger
from cai.util import append_instructions

_GRIT_INSTRUCTIONS: str | None = None
_SKILL_INSTRUCTIONS: Dict[str, str] = {}  # Cache skill instructions per agent
_MCP_PREFERENCE_INSTRUCTIONS: str | None = None


def _strip_yaml_front_matter(text: str) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return text
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            return "\n".join(lines[idx + 1 :])
    return text


def _load_grit_instructions() -> str:
    global _GRIT_INSTRUCTIONS
    if _GRIT_INSTRUCTIONS is not None:
        return _GRIT_INSTRUCTIONS
    grit_path = os.getenv("CAI_GRIT_PATH", "docs/grit.md")
    try:
        grit_text = Path(grit_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        logger.debug("Grit instructions not loaded from %s: %s", grit_path, exc)
        _GRIT_INSTRUCTIONS = ""
        return _GRIT_INSTRUCTIONS
    grit_text = _strip_yaml_front_matter(grit_text).strip()
    _GRIT_INSTRUCTIONS = grit_text
    return _GRIT_INSTRUCTIONS


def _load_mcp_preference_instructions(mcp_tools: list) -> str:
    """
    Generate instructions to prefer MCP tools over built-in alternatives.
    
    Args:
        mcp_tools: List of MCP tools available to the agent
        
    Returns:
        Instructions string telling the agent to prefer MCP tools
    """
    if not mcp_tools:
        return ""
    
    tool_names = [t.name for t in mcp_tools]
    
    instructions_parts = ["\n## MCP Tool Preferences\n"]
    instructions_parts.append("You have access to advanced MCP tools. Prefer these over basic shell commands:\n")
    
    # edit_file from morph
    if "edit_file" in tool_names:
        instructions_parts.append(
            "- **edit_file**: Use this for ALL file edits. It's 10x faster than manual editing and "
            "prevents context pollution. Use `// ... existing code ...` placeholders for unchanged sections.\n"
        )
    
    # warpgrep from morph
    if "warpgrep_codebase_search" in tool_names:
        instructions_parts.append(
            "- **warpgrep_codebase_search**: Use this for semantic codebase exploration. "
            "Better than grep for finding relevant code by meaning, not just text.\n"
        )
    
    # Serena tools
    serena_tools = ["find_symbol", "get_symbols_overview", "find_referencing_symbols", 
                    "replace_symbol_body", "insert_after_symbol", "insert_before_symbol"]
    available_serena = [t for t in serena_tools if t in tool_names]
    if available_serena:
        instructions_parts.append(
            f"- **Serena tools** ({', '.join(available_serena)}): Use for semantic code analysis. "
            "These understand code structure (classes, methods, symbols) rather than just text.\n"
        )
    
    # Serena's list_dir if available (not the shell one)
    if "list_dir" in tool_names:
        # Check if it's the Serena one by looking at the tool description
        for t in mcp_tools:
            if t.name == "list_dir" and "JSON" in (t.description or ""):
                instructions_parts.append(
                    "- **list_dir** (MCP): Returns structured JSON with file metadata. "
                    "Prefer over shell `ls` commands.\n"
                )
                break
    
    # Slither MCP tools for smart contract analysis
    slither_tools = [
        "list_contracts", "get_contract", "get_contract_source", "get_function_source",
        "list_functions", "get_function_callees", "get_inherited_contracts", "get_derived_contracts",
        "list_function_implementations", "get_function_callers", "list_detectors", "run_detectors",
        "search_contracts", "search_functions", "get_project_overview", "find_dead_code",
        "export_call_graph", "get_contract_dependencies", "analyze_state_variables",
        "get_storage_layout", "analyze_events", "analyze_modifiers", "analyze_low_level_calls",
        "analyze_reentrancy_patterns", "analyze_access_control", "analyze_erc4626_vault",
        "analyze_amm_patterns", "analyze_lending_pool", "analyze_cross_contract_calls",
        "analyze_invariants", "run_custom_detectors"
    ]
    available_slither = [t for t in tool_names if t in slither_tools]
    if available_slither:
        # Group by category for clearer instructions
        analysis_tools = [t for t in available_slither if t.startswith("analyze_")]
        detector_tools = [t for t in available_slither if "detector" in t]
        query_tools = [t for t in available_slither if t.startswith(("list_", "get_", "search_", "find_", "export_"))]
        
        instructions_parts.append(
            "- **Slither MCP** (smart contract static analysis):\n"
        )
        if detector_tools:
            instructions_parts.append(
                f"  - Detectors: `run_detectors` to find vulnerabilities, `list_detectors` for available checks\n"
            )
        if analysis_tools:
            instructions_parts.append(
                f"  - Analysis: {', '.join(f'`{t}`' for t in analysis_tools[:5])}{'...' if len(analysis_tools) > 5 else ''}\n"
            )
        if query_tools:
            instructions_parts.append(
                f"  - Query: `get_contract_source`, `list_functions`, `search_contracts` for code exploration\n"
            )
        instructions_parts.append(
            "  Use Slither tools for deep smart contract analysis instead of manual code reading.\n"
        )
    
    # Mythril MCP tools
    mythril_tools = [t for t in tool_names if "mythril" in t.lower()]
    if mythril_tools:
        instructions_parts.append(
            f"- **Mythril tools** ({', '.join(mythril_tools)}): Use for symbolic execution "
            "and deep vulnerability analysis of smart contracts.\n"
        )
    
    # General preference
    instructions_parts.append(
        "\nIMPORTANT: Prefer MCP tools over shell commands like `cat`, `ls`, `grep` when "
        "an MCP equivalent is available. MCP tools are faster, smarter, and produce better results."
    )
    
    return "".join(instructions_parts)


def _load_skill_instructions(agent_name: str) -> str:
    """
    Load skill instructions for an agent.
    
    Skills are loaded from:
    1. ~/.cai/skills/
    2. .cai/skills/ (project directory)
    3. Built-in skills (src/cai/skills/builtin/)
    
    Args:
        agent_name: Name of the agent to load skills for
        
    Returns:
        Combined skill instructions as a string
    """
    # Check if skills are disabled
    if os.getenv("CAI_SKILLS", "true").lower() == "false":
        return ""
    
    # Check cache first
    if agent_name in _SKILL_INSTRUCTIONS:
        return _SKILL_INSTRUCTIONS[agent_name]
    
    try:
        from cai.skills import load_skills_for_agent, discover_skills
        
        # Ensure skills are discovered
        discover_skills()
        
        # Load skills for this agent
        skill_content = load_skills_for_agent(agent_name)
        _SKILL_INSTRUCTIONS[agent_name] = skill_content
        
        if skill_content:
            logger.debug("Loaded skills for agent %s", agent_name)
        
        return skill_content
    except ImportError as exc:
        logger.debug("Skills module not available: %s", exc)
        return ""
    except Exception as exc:
        logger.debug("Failed to load skills for agent %s: %s", agent_name, exc)
        return ""


def create_generic_agent_factory(
    agent_module_path: str, agent_var_name: str
) -> Callable[[str|None, str|None], Agent]:
    """
    Create a generic factory function for any agent.

    Args:
        agent_module_path: Full module path to the agent (e.g., 'cai.agents.one_tool')
        agent_var_name: Name of the agent variable in the module (e.g., 'one_tool_agent')

    Returns:
        A factory function that creates new instances of the agent
    """

    def factory(model_override: str | None = None, custom_name: str | None = None, agent_id: str | None = None):
        # Import the module
        module = importlib.import_module(agent_module_path)

        # Get the original agent instance
        original_agent = getattr(module, agent_var_name)

        # Get model configuration - check multiple sources
        model_name = model_override  # First priority: explicit override
        
        if not model_name:
            # Second priority: agent-specific environment variable
            agent_key = agent_var_name.upper()
            model_name = os.getenv(f"CAI_{agent_key}_MODEL")
        
        if not model_name:
            # Third priority: global CAI_MODEL
            model_name = os.environ.get("CAI_MODEL", "alias1")
            
            
        api_key = os.getenv("OPENAI_API_KEY", "sk-placeholder-key-for-local-models")

        # Create a new model instance with the original agent name
        # Custom name is only for display purposes, not for the model
        new_model = OpenAIChatCompletionsModel(
            model=model_name,
            openai_client=AsyncOpenAI(api_key=api_key),
            agent_name=original_agent.name,  # Always use original agent name
            agent_id=agent_id,
            agent_type=agent_var_name,  # Pass the agent type for registry
        )
        
        # Mark as parallel agent if running in parallel mode
        parallel_count = int(os.getenv("CAI_PARALLEL", "1"))
        if parallel_count > 1 and agent_id and agent_id.startswith("P"):
            new_model._is_parallel_agent = True

        # Clone the agent with the new model
        cloned_agent = original_agent.clone(model=new_model)

        grit_instructions = _load_grit_instructions()
        if grit_instructions:
            append_instructions(cloned_agent, "\n\n" + grit_instructions)
        
        # Load and append skill instructions
        skill_instructions = _load_skill_instructions(original_agent.name)
        if skill_instructions:
            append_instructions(cloned_agent, "\n\n" + skill_instructions)
        
        # Update agent name if custom name was provided
        if custom_name:
            cloned_agent.name = custom_name
            
        # Check if this agent has any MCP tools configured
        mcp_tools = []
        try:
            from cai.repl.commands.mcp import get_mcp_tools_for_agent
            
            # Get MCP tools for this agent and add them
            mcp_tools = get_mcp_tools_for_agent(agent_var_name)
            if mcp_tools:
                # Ensure the agent has tools list
                if not hasattr(cloned_agent, 'tools'):
                    cloned_agent.tools = []
                
                # Remove any existing tools with the same names to avoid duplicates
                existing_tool_names = {t.name for t in mcp_tools}
                cloned_agent.tools = [t for t in cloned_agent.tools if t.name not in existing_tool_names]
                
                # Add the MCP tools
                cloned_agent.tools.extend(mcp_tools)
                
                # Add instructions to prefer MCP tools
                mcp_instructions = _load_mcp_preference_instructions(mcp_tools)
                if mcp_instructions:
                    append_instructions(cloned_agent, mcp_instructions)
                
        except ImportError:
            # MCP command not available, skip
            pass
            
        return cloned_agent

    return factory


def discover_agent_factories() -> Dict[str, Callable[[], Agent]]:
    """
    Dynamically discover all agents and create factories for them.

    Returns:
        Dictionary mapping agent names to factory functions
    """
    import pkgutil

    import cai.agents

    agent_factories = {}

    # Scan the agents module for all agent definitions
    for importer, modname, ispkg in pkgutil.iter_modules(
        cai.agents.__path__, cai.agents.__name__ + "."
    ):
        if ispkg:
            continue  # Skip packages like 'patterns' and 'meta'

        try:
            # Import the module
            module = importlib.import_module(modname)

            # Look for Agent instances
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)
                if isinstance(attr, Agent):
                    # Create a factory for this agent
                    agent_name = attr_name.lower()
                    agent_factories[agent_name] = create_generic_agent_factory(modname, attr_name)

        except Exception:
            # Skip modules that fail to import
            continue

    # Also scan patterns subdirectory
    patterns_path = os.path.join(os.path.dirname(cai.agents.__file__), "patterns")
    if os.path.exists(patterns_path):
        for importer, modname, ispkg in pkgutil.iter_modules(
            [patterns_path], cai.agents.__name__ + ".patterns."
        ):
            if ispkg:
                continue

            try:
                module = importlib.import_module(modname)

                for attr_name in dir(module):
                    if attr_name.startswith("_"):
                        continue

                    attr = getattr(module, attr_name)
                    if isinstance(attr, Agent):
                        agent_name = attr_name.lower()
                        agent_factories[agent_name] = create_generic_agent_factory(
                            modname, attr_name
                        )

            except Exception:
                continue

    return agent_factories


# Global registry of agent factories
AGENT_FACTORIES = None


def get_agent_factory(agent_name: str) -> Callable[[], Agent]:
    """
    Get a factory function for creating instances of the specified agent.

    Args:
        agent_name: Name of the agent

    Returns:
        Factory function that creates new agent instances

    Raises:
        ValueError: If agent not found
    """
    global AGENT_FACTORIES

    # Lazy initialization
    if AGENT_FACTORIES is None:
        AGENT_FACTORIES = discover_agent_factories()

    agent_name_lower = agent_name.lower()

    if agent_name_lower not in AGENT_FACTORIES:
        raise ValueError(
            f"Agent '{agent_name}' not found. Available agents: {list(AGENT_FACTORIES.keys())}"
        )

    return AGENT_FACTORIES[agent_name_lower]
