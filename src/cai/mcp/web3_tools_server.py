from __future__ import annotations

from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from cai.tools.web3_security.policy import parse_policy_level
from cai.tools.web3_security.runner import describe_plugin, list_plugins, run_plugin
from cai.tools.web3_security.schemas import ExposureSurface, PluginRunRequest


mcp = FastMCP("web3-tools")


@mcp.tool()
def list_web3_plugins() -> Dict[str, Any]:
    """List all available Web3 security plugins exposed on the MCP surface.

    Returns a dict with a 'plugins' list. Each entry has: name, description,
    category, risk_level, requires_aggressive, supports_fork_test,
    supports_formal_verification, mutates_state, chain_type.

    Use this first to discover available plugins before calling describe or run.
    """
    return list_plugins(ExposureSurface.MCP)


@mcp.tool()
def describe_web3_plugin(plugin_name: str) -> Dict[str, Any]:
    """Get full metadata and input schema for a named Web3 security plugin.

    Args:
        plugin_name: The plugin name (from list_web3_plugins).

    Returns a dict with: name, description, category, risk_level,
    requires_aggressive, input_schema, supports_fork_test,
    supports_formal_verification, mutates_state, chain_type.

    Always call this before run_web3_plugin to know the required input_schema.
    """
    return describe_plugin(plugin_name)


@mcp.tool()
def run_web3_plugin(
    plugin_name: str,
    args: Dict[str, Any] | None = None,
    policy_level: str = "safe",
    allow_aggressive: bool = False,
    dry_run: bool = False,
    timeout_sec: int = 30,
) -> Dict[str, Any]:
    """Execute a Web3 security plugin with policy and safety controls.

    Args:
        plugin_name: The plugin to run (from list_web3_plugins).
        args: Plugin input arguments matching the plugin's input_schema.
        policy_level: 'safe', 'balanced', or 'aggressive'. Default 'safe'.
        allow_aggressive: Set True to allow aggressive-risk plugins. Default False.
        dry_run: If True, validate policy/exposure without executing. Default False.
        timeout_sec: Max execution time in seconds. Default 30.

    Returns a normalized envelope with: ok, plugin, request_id, input,
    result, error (with error.type for retries), and meta (risk_level,
    aggressive, duration_ms, timestamp, version).

    Recommended flow: list -> describe -> run(dry_run=True) -> run(dry_run=False).
    """
    request = PluginRunRequest(
        plugin_name=plugin_name,
        args=args or {},
        policy_level=parse_policy_level(policy_level),
        allow_aggressive=allow_aggressive,
        dry_run=dry_run,
        timeout_sec=timeout_sec,
        exposure_surface=ExposureSurface.MCP,
    )
    return run_plugin(request)


if __name__ == "__main__":
    mcp.run(transport="stdio")

