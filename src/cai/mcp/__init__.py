"""
MCP (Model Context Protocol) auto-loading and configuration for CAI.

This module provides automatic loading of MCP servers from a configuration file,
eliminating the need to manually run /mcp load commands every session.

Configuration is stored in ~/.cai/mcp.yaml or .cai/mcp.yaml (project-level).
"""

from .config import (
    MCPConfig,
    MCPServerConfig,
    load_mcp_config,
    save_mcp_config,
    get_config_path,
    auto_load_mcp_servers,
)

__all__ = [
    "MCPConfig",
    "MCPServerConfig", 
    "load_mcp_config",
    "save_mcp_config",
    "get_config_path",
    "auto_load_mcp_servers",
]
