"""
MCP Configuration loader and auto-loading functionality.

Supports loading MCP servers from:
1. ~/.cai/mcp.yaml (user-level, primary)
2. .cai/mcp.yaml (project-level, merged)

Example configuration:

```yaml
# ~/.cai/mcp.yaml
servers:
  serena:
    type: stdio
    command: uv
    args:
      - run
      - --directory
      - /home/dok/MCP/serena_v-web3
      - serena-mcp-server
      - --context
      - ide-assistant
      - --mode
      - interactive
    enabled: true
    
  slither-mcp:
    type: stdio
    command: uv
    args: ["run", "--directory", "/home/dok/MCP/slither-mcp", "slither-mcp"]
    enabled: true

  morphmcp:
    type: stdio
    command: bash
    args: ["-c", "export MORPH_API_KEY='...' && exec npx -y @morphllm/morphmcp"]
    enabled: true

  burp:
    type: sse
    url: http://localhost:9876/sse
    enabled: false  # disabled by default

# Which agents get which MCP tools automatically
bindings:
  security_agent: [slither-mcp, serena]
  one_tool_agent: [serena, morphmcp]
  audit_agent: [slither-mcp, serena]
  "*": [morphmcp]  # wildcard: all agents get morphmcp

# Global settings
settings:
  auto_load: true  # Enable/disable auto-loading on startup
  timeout: 30      # Connection timeout in seconds
  verbose: false   # Show loading progress
```
"""

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Try to import yaml, fall back to json if not available
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    import json


@dataclass
class MCPServerConfig:
    """Configuration for a single MCP server."""
    name: str
    type: str  # "stdio" or "sse"
    enabled: bool = True
    
    # For stdio servers
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None
    
    # For SSE servers
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    timeout: int = 10
    sse_read_timeout: int = 300
    
    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "MCPServerConfig":
        """Create MCPServerConfig from a dictionary."""
        return cls(
            name=name,
            type=data.get("type", "stdio"),
            enabled=data.get("enabled", True),
            command=data.get("command"),
            args=data.get("args", []),
            env=data.get("env"),
            cwd=data.get("cwd"),
            url=data.get("url"),
            headers=data.get("headers"),
            timeout=data.get("timeout", 10),
            sse_read_timeout=data.get("sse_read_timeout", 300),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "type": self.type,
            "enabled": self.enabled,
        }
        
        if self.type == "stdio":
            if self.command:
                result["command"] = self.command
            if self.args:
                result["args"] = self.args
            if self.env:
                result["env"] = self.env
            if self.cwd:
                result["cwd"] = self.cwd
        elif self.type == "sse":
            if self.url:
                result["url"] = self.url
            if self.headers:
                result["headers"] = self.headers
            if self.timeout != 10:
                result["timeout"] = self.timeout
            if self.sse_read_timeout != 300:
                result["sse_read_timeout"] = self.sse_read_timeout
                
        return result


@dataclass 
class MCPConfig:
    """Complete MCP configuration."""
    servers: Dict[str, MCPServerConfig] = field(default_factory=dict)
    bindings: Dict[str, List[str]] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=lambda: {
        "auto_load": True,
        "timeout": 30,
        "verbose": False,
    })
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPConfig":
        """Create MCPConfig from a dictionary."""
        servers = {}
        for name, server_data in data.get("servers", {}).items():
            servers[name] = MCPServerConfig.from_dict(name, server_data)
            
        return cls(
            servers=servers,
            bindings=data.get("bindings", {}),
            settings=data.get("settings", {
                "auto_load": True,
                "timeout": 30,
                "verbose": False,
            }),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "servers": {name: server.to_dict() for name, server in self.servers.items()},
            "bindings": self.bindings,
            "settings": self.settings,
        }
    
    def get_servers_for_agent(self, agent_name: str) -> List[str]:
        """Get list of MCP server names that should be bound to an agent."""
        servers = []
        
        # Check exact match
        if agent_name.lower() in self.bindings:
            servers.extend(self.bindings[agent_name.lower()])
        
        # Check wildcard
        if "*" in self.bindings:
            for server in self.bindings["*"]:
                if server not in servers:
                    servers.append(server)
                    
        return servers


def get_config_path(project_level: bool = False) -> Path:
    """
    Get the path to the MCP configuration file.
    
    Args:
        project_level: If True, return project-level config path (.cai/mcp.yaml)
                      If False, return user-level config path (~/.cai/mcp.yaml)
    
    Returns:
        Path to the configuration file
    """
    if project_level:
        return Path.cwd() / ".cai" / "mcp.yaml"
    else:
        return Path.home() / ".cai" / "mcp.yaml"


def load_mcp_config() -> MCPConfig:
    """
    Load MCP configuration from file(s).
    
    Loads from both user-level (~/.cai/mcp.yaml) and project-level (.cai/mcp.yaml),
    merging them with project-level taking precedence.
    
    Returns:
        MCPConfig object with merged configuration
    """
    config = MCPConfig()
    
    # Load user-level config first
    user_config_path = get_config_path(project_level=False)
    if user_config_path.exists():
        try:
            user_config = _load_config_file(user_config_path)
            config = MCPConfig.from_dict(user_config)
            logger.debug(f"Loaded user MCP config from {user_config_path}")
        except Exception as e:
            logger.warning(f"Failed to load user MCP config: {e}")
    
    # Load and merge project-level config
    project_config_path = get_config_path(project_level=True)
    if project_config_path.exists():
        try:
            project_config = _load_config_file(project_config_path)
            project_mcp_config = MCPConfig.from_dict(project_config)
            
            # Merge: project overrides user
            config.servers.update(project_mcp_config.servers)
            config.bindings.update(project_mcp_config.bindings)
            config.settings.update(project_mcp_config.settings)
            
            logger.debug(f"Merged project MCP config from {project_config_path}")
        except Exception as e:
            logger.warning(f"Failed to load project MCP config: {e}")
    
    return config


def _load_config_file(path: Path) -> Dict[str, Any]:
    """Load a configuration file (YAML or JSON)."""
    content = path.read_text(encoding="utf-8")
    
    if HAS_YAML:
        return yaml.safe_load(content) or {}
    else:
        # Fallback to JSON if PyYAML not installed
        return json.loads(content)


def save_mcp_config(config: MCPConfig, project_level: bool = False) -> Path:
    """
    Save MCP configuration to file.
    
    Args:
        config: MCPConfig object to save
        project_level: If True, save to project-level config
        
    Returns:
        Path to the saved configuration file
    """
    config_path = get_config_path(project_level=project_level)
    
    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = config.to_dict()
    
    if HAS_YAML:
        content = yaml.dump(data, default_flow_style=False, sort_keys=False)
    else:
        content = json.dumps(data, indent=2)
    
    config_path.write_text(content, encoding="utf-8")
    logger.info(f"Saved MCP config to {config_path}")
    
    return config_path


def auto_load_mcp_servers(verbose: bool = False) -> Dict[str, bool]:
    """
    Auto-load all enabled MCP servers from configuration.
    
    This is called during CAI startup to automatically connect to
    configured MCP servers.
    
    Args:
        verbose: If True, print loading progress
        
    Returns:
        Dictionary mapping server names to success status
    """
    from rich.console import Console
    console = Console()
    
    config = load_mcp_config()
    
    # Check if auto-load is enabled
    if not config.settings.get("auto_load", True):
        if verbose:
            console.print("[dim]MCP auto-load disabled in config[/dim]")
        return {}
    
    results = {}
    enabled_servers = [
        (name, server) 
        for name, server in config.servers.items() 
        if server.enabled
    ]
    
    if not enabled_servers:
        if verbose:
            console.print("[dim]No MCP servers configured for auto-load[/dim]")
        return {}
    
    if verbose:
        console.print(f"[cyan]Auto-loading {len(enabled_servers)} MCP server(s)...[/cyan]")
    
    # Import the MCP command infrastructure
    try:
        from cai.repl.commands.mcp import (
            _GLOBAL_MCP_SERVERS,
            _AGENT_MCP_ASSOCIATIONS,
            MCPServerSse,
            MCPServerStdio,
        )
    except ImportError as e:
        logger.warning(f"MCP command module not available: {e}")
        return {}
    
    import asyncio
    import warnings
    
    async def load_server(name: str, server_config: MCPServerConfig) -> bool:
        """Load a single MCP server."""
        try:
            if name in _GLOBAL_MCP_SERVERS:
                # Already loaded
                return True
                
            if server_config.type == "stdio":
                from cai.sdk.agents.mcp import MCPServerStdioParams
                
                params: MCPServerStdioParams = {
                    "command": server_config.command,
                    "args": server_config.args,
                }
                if server_config.env:
                    params["env"] = server_config.env
                if server_config.cwd:
                    params["cwd"] = server_config.cwd
                    
                server = MCPServerStdio(params, name=name, cache_tools_list=True)
                
            elif server_config.type == "sse":
                from cai.sdk.agents.mcp import MCPServerSseParams
                
                params: MCPServerSseParams = {
                    "url": server_config.url,
                    "timeout": server_config.timeout,
                    "sse_read_timeout": server_config.sse_read_timeout,
                }
                if server_config.headers:
                    params["headers"] = server_config.headers
                    
                server = MCPServerSse(params, name=name, cache_tools_list=True)
            else:
                logger.warning(f"Unknown server type: {server_config.type}")
                return False
            
            # Connect with timeout
            timeout = config.settings.get("timeout", 30)
            await asyncio.wait_for(server.connect(), timeout=timeout)
            
            # Verify by listing tools
            tools = await server.list_tools()
            
            # Register globally
            _GLOBAL_MCP_SERVERS[name] = server
            
            if verbose:
                console.print(f"  [green]✓[/green] {name} ({len(tools)} tools)")
            
            return True
            
        except asyncio.TimeoutError:
            if verbose:
                console.print(f"  [red]✗[/red] {name} (timeout)")
            logger.warning(f"Timeout loading MCP server {name}")
            return False
        except Exception as e:
            if verbose:
                console.print(f"  [red]✗[/red] {name} ({str(e)[:50]})")
            logger.warning(f"Failed to load MCP server {name}: {e}")
            return False
    
    async def load_all_servers():
        """Load all servers concurrently."""
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=RuntimeWarning)
            warnings.filterwarnings("ignore", message=".*asynchronous generator.*")
            
            tasks = [
                load_server(name, server_config)
                for name, server_config in enabled_servers
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)
    
    # Run the async loading
    try:
        loop = asyncio.get_running_loop()
        import concurrent.futures
        
        def run_in_thread():
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                return new_loop.run_until_complete(load_all_servers())
            finally:
                new_loop.close()
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(run_in_thread)
            load_results = future.result(timeout=60)
            
    except RuntimeError:
        # No running loop
        load_results = asyncio.run(load_all_servers())
    
    # Process results
    for i, (name, _) in enumerate(enabled_servers):
        result = load_results[i]
        if isinstance(result, Exception):
            results[name] = False
        else:
            results[name] = bool(result)
    
    # Now set up agent bindings
    _setup_agent_bindings(config, verbose)
    
    # Summary
    success_count = sum(1 for v in results.values() if v)
    if verbose:
        console.print(
            f"[cyan]MCP auto-load complete: {success_count}/{len(enabled_servers)} servers loaded[/cyan]"
        )
    
    return results


def _setup_agent_bindings(config: MCPConfig, verbose: bool = False):
    """Set up agent-MCP bindings from configuration."""
    from rich.console import Console
    console = Console()
    
    try:
        from cai.repl.commands.mcp import (
            _GLOBAL_MCP_SERVERS,
            _AGENT_MCP_ASSOCIATIONS,
        )
    except ImportError:
        return
    
    # Process bindings
    for agent_name, server_names in config.bindings.items():
        if agent_name == "*":
            continue  # Wildcard handled separately
            
        agent_name_lower = agent_name.lower()
        if agent_name_lower not in _AGENT_MCP_ASSOCIATIONS:
            _AGENT_MCP_ASSOCIATIONS[agent_name_lower] = []
        
        for server_name in server_names:
            if server_name in _GLOBAL_MCP_SERVERS:
                if server_name not in _AGENT_MCP_ASSOCIATIONS[agent_name_lower]:
                    _AGENT_MCP_ASSOCIATIONS[agent_name_lower].append(server_name)
    
    if verbose and config.bindings:
        bound_count = sum(
            len(servers) for agent, servers in _AGENT_MCP_ASSOCIATIONS.items()
        )
        console.print(f"[dim]Set up {bound_count} agent-MCP bindings[/dim]")


def create_default_config_from_current(save: bool = True) -> MCPConfig:
    """
    Create a config from currently loaded MCP servers.
    
    Useful for saving the current state to a config file.
    
    Args:
        save: If True, save the config to ~/.cai/mcp.yaml
        
    Returns:
        MCPConfig object
    """
    try:
        from cai.repl.commands.mcp import (
            _GLOBAL_MCP_SERVERS,
            _AGENT_MCP_ASSOCIATIONS,
            MCPServerSse,
            MCPServerStdio,
        )
    except ImportError:
        return MCPConfig()
    
    servers = {}
    
    for name, server in _GLOBAL_MCP_SERVERS.items():
        if isinstance(server, MCPServerStdio):
            servers[name] = MCPServerConfig(
                name=name,
                type="stdio",
                enabled=True,
                command=server.params.command,
                args=list(server.params.args) if server.params.args else [],
                env=getattr(server.params, "env", None),
                cwd=getattr(server.params, "cwd", None),
            )
        elif isinstance(server, MCPServerSse):
            servers[name] = MCPServerConfig(
                name=name,
                type="sse",
                enabled=True,
                url=server.params.get("url"),
                headers=server.params.get("headers"),
                timeout=server.params.get("timeout", 10),
                sse_read_timeout=server.params.get("sse_read_timeout", 300),
            )
    
    config = MCPConfig(
        servers=servers,
        bindings=dict(_AGENT_MCP_ASSOCIATIONS),
        settings={
            "auto_load": True,
            "timeout": 30,
            "verbose": True,
        },
    )
    
    if save:
        save_mcp_config(config)
    
    return config
