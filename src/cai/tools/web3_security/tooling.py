"""
Web3 tooling status utilities.
"""

import json
from cai.sdk.agents import function_tool
from .config import get_all_tool_paths, get_available_tools


@function_tool
def web3_tool_status(ctf=None) -> str:
    """
    Report configured Web3 tool paths and availability.

    Returns:
        JSON string with tool paths and availability flags.
    """
    tool_paths = get_all_tool_paths()
    availability = get_available_tools()
    missing = [name for name, ok in availability.items() if not ok]
    return json.dumps({
        "tool_paths": tool_paths,
        "available": availability,
        "missing": missing,
    }, indent=2)
