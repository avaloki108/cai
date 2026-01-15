"""
Configuration for Web3 security tools paths.

This module allows customization of tool installation paths through
environment variables or direct configuration.
"""

import os
from typing import Dict, Optional

# Default tool paths
DEFAULT_TOOL_PATHS = {
    'slither': '/home/dok/tools/W3-AUDIT/slither/slither',
    'mythril': '/home/dok/tools/mythril2.0/myth',
    'securify': '/home/dok/tools/securify2.5/securify',
    'echidna': '/home/dok/tools/echidna/echidna',
    'medusa': '/home/dok/tools/medusa/medusa',
    'fuzz_utils_base': '/home/dok/tools/fuzz-utils',
    'gambit': '/home/dok/tools/W3-AUDIT/gambit/gambit',
    'clorgetizer': '/home/dok/tools/W3-AUDIT/clorgetizer/clorgetizer',
    'certora_prover': '/home/dok/tools/W3-AUDIT/certora-prover/certoraRun',
    'oyente_plus': '/home/dok/tools/W3-AUDIT/oyente-plus/oyente',
    'auditor_framework': '/home/dok/tools/auditor-framework/auditor',
}

# Environment variable overrides
ENV_VAR_MAP = {
    'slither': 'WEB3_SLITHER_PATH',
    'mythril': 'WEB3_MYTHRIL_PATH',
    'securify': 'WEB3_SECURIFY_PATH',
    'echidna': 'WEB3_ECHIDNA_PATH',
    'medusa': 'WEB3_MEDUSA_PATH',
    'fuzz_utils_base': 'WEB3_FUZZ_UTILS_PATH',
    'gambit': 'WEB3_GAMBIT_PATH',
    'clorgetizer': 'WEB3_CLORGETIZER_PATH',
    'certora_prover': 'WEB3_CERTORA_PROVER_PATH',
    'oyente_plus': 'WEB3_OYENTE_PLUS_PATH',
    'auditor_framework': 'WEB3_AUDITOR_FRAMEWORK_PATH',
}


def get_tool_path(tool_name: str) -> str:
    """
    Get the path for a specific tool.

    Checks environment variables first, then falls back to defaults.
    Also checks if the tool is in PATH.

    Args:
        tool_name: Name of the tool (e.g., 'slither', 'mythril')

    Returns:
        str: Path to the tool executable
    """
    # Check environment variable
    env_var = ENV_VAR_MAP.get(tool_name)
    if env_var and os.getenv(env_var):
        return os.getenv(env_var)

    # Check if tool is in PATH
    from shutil import which
    tool_in_path = which(tool_name)
    if tool_in_path:
        return tool_in_path

    # Fall back to default
    return DEFAULT_TOOL_PATHS.get(tool_name, tool_name)


def check_tool_available(tool_name: str) -> bool:
    """
    Check if a tool is available at its configured path.

    Args:
        tool_name: Name of the tool

    Returns:
        bool: True if tool exists and is executable
    """
    tool_path = get_tool_path(tool_name)
    return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)


def get_all_tool_paths() -> Dict[str, str]:
    """
    Get all configured tool paths.

    Returns:
        Dict mapping tool names to their paths
    """
    return {tool: get_tool_path(tool) for tool in DEFAULT_TOOL_PATHS.keys()}


def get_available_tools() -> Dict[str, bool]:
    """
    Check which tools are available.

    Returns:
        Dict mapping tool names to availability status
    """
    return {tool: check_tool_available(tool) for tool in DEFAULT_TOOL_PATHS.keys()}


# Export configured paths
SLITHER_PATH = get_tool_path('slither')
MYTHRIL_PATH = get_tool_path('mythril')
SECURIFY_PATH = get_tool_path('securify')
ECHIDNA_PATH = get_tool_path('echidna')
MEDUSA_PATH = get_tool_path('medusa')
FUZZ_UTILS_BASE_PATH = get_tool_path('fuzz_utils_base')
GAMBIT_PATH = get_tool_path('gambit')
CLORGETIZER_PATH = get_tool_path('clorgetizer')
CERTORA_PROVER_PATH = get_tool_path('certora_prover')
OYENTE_PLUS_PATH = get_tool_path('oyente_plus')
AUDITOR_FRAMEWORK_PATH = get_tool_path('auditor_framework')
