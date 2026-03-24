"""
Hunt command for CAI REPL.
Quickstart for interactive web3 bug hunting:
set workspace to a path and switch to web3_bug_bounty_agent.
"""
import json
import os
import time
import uuid
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel

from cai.repl.commands.base import Command, handle_command, register_command
from cai.tools.web3_security.policy import parse_policy_level
from cai.tools.web3_security.runner import describe_plugin, list_plugins, run_plugin
from cai.tools.web3_security.schemas import ExposureSurface, PluginRunRequest

console = Console()
DEBUG_LOG_PATH = "/home/dok/tools/cai/.cursor/debug-7cde7a.log"
DEBUG_SESSION_ID = "7cde7a"


def _debug_log(*, hypothesis_id: str, location: str, message: str, data: dict) -> None:
    payload = {
        "sessionId": DEBUG_SESSION_ID,
        "id": f"log_{uuid.uuid4().hex}",
        "timestamp": int(time.time() * 1000),
        "location": location,
        "message": message,
        "data": data,
        "runId": os.getenv("CAI_DEBUG_RUN_ID", "pre-fix"),
        "hypothesisId": hypothesis_id,
    }
    try:
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass

HUNT_NO_ARGS_PANEL = """[bold]Web3 Hunt[/bold] — Interactive hunt quickstart. Sets workspace to a repo and switches to [cyan]web3_bug_bounty_agent[/cyan].

[bold]Mode contract[/bold]
  - [cyan]Interactive[/cyan] ([green]/hunt[/green]): agent-led exploration and tool orchestration
  - [cyan]Deterministic[/cyan]: run [green]EliteWeb3Pipeline[/green] programmatically for reproducible stage metrics and verdicts
  - [cyan]Judge-gated[/cyan]: use [green]web3_hunter_judge_poc_pattern[/green] (Hunter → Judge → PoC)

[bold yellow]Usage[/bold yellow]
  [green]/hunt <location>[/green]   Path to the web3 project (absolute or relative)

[bold cyan]Examples[/bold cyan]
  [green]/hunt /home/user/web3_2/aqua[/green]
  [green]/hunt ./my-contracts[/green]

After running [green]/hunt <path>[/green], ask to audit the repo, run static analysis, or describe the protocol. Quality bar: attacker-exploitable only; clear attack path and measurable impact."""

HUNT_PLUGINS_USAGE = """[bold]Web3 Hunt Plugins[/bold]

[bold yellow]Usage[/bold yellow]
  [green]/hunt plugins list[/green]
  [green]/hunt plugins describe <plugin_name>[/green]
  [green]/hunt plugins run <plugin_name> --args '{"k":"v"}'[/green]
  [green]/hunt plugins run <plugin_name> --args-file args.json[/green]
  [green]/hunt plugins run <plugin_name> --policy aggressive --allow-aggressive [--dry-run][/green]
"""

DEFAULT_HUNT_AGENT = "web3_bug_bounty_agent"
DEFAULT_HUNT_KICKOFF_PROMPT = (
    "Run a full exploitability-first Web3 bug hunt for the active workspace. "
    "Focus on novel and edge-case vulnerabilities only. "
    "Start with fast repo context mapping, then generate ranked hypotheses, "
    "and validate only permissionless attack paths with measurable impact."
)


def _is_truthy(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _build_hunt_kickoff_prompt(path: str) -> str:
    prompt_template = os.getenv("CAI_HUNT_PROMPT_TEMPLATE", "").strip()
    if prompt_template:
        try:
            return prompt_template.format(path=path)
        except Exception:
            return prompt_template
    return f"{DEFAULT_HUNT_KICKOFF_PROMPT} Target path: {path}"


class HuntCommand(Command):
    """Command for web3 audit quickstart: set workspace to <location> and switch to web3 bug bounty agent."""

    def __init__(self):
        super().__init__(
            name="/hunt",
            description="Web3 audit quickstart: set workspace to <location> and switch to web3 bug bounty agent.",
            aliases=[],
        )

    def handle(self, args: Optional[List[str]] = None) -> bool:
        # region agent log
        _debug_log(
            hypothesis_id="H1",
            location="src/cai/repl/commands/hunt.py:handle",
            message="Entered /hunt command",
            data={"args": args or [], "cwd": os.getcwd()},
        )
        # endregion
        if not args or len(args) < 1:
            os.environ.pop("CAI_HUNT_AUTO_PROMPT", None)
            # region agent log
            _debug_log(
                hypothesis_id="H1",
                location="src/cai/repl/commands/hunt.py:handle",
                message="/hunt invoked without args",
                data={
                    "workspace_dir": os.getenv("CAI_WORKSPACE_DIR"),
                    "workspace": os.getenv("CAI_WORKSPACE"),
                },
            )
            # endregion
            console.print(Panel(HUNT_NO_ARGS_PANEL, title="Web3 Hunt — Quick Start", border_style="cyan"))
            return True

        if args[0].strip().lower() == "plugins":
            os.environ.pop("CAI_HUNT_AUTO_PROMPT", None)
            return self._handle_plugins(args[1:] if len(args) > 1 else [])

        location = args[0].strip()
        path = os.path.abspath(os.path.expanduser(location))

        if not os.path.exists(path):
            console.print(f"[red]Path does not exist: {path}[/red]")
            return False

        if not os.path.isdir(path):
            console.print(f"[red]Not a directory: {path}[/red]")
            return False

        workspace_name = os.path.basename(path)
        if not workspace_name or not all(
            c.isalnum() or c in ["_", "-"] for c in workspace_name
        ):
            console.print(
                "[red]Workspace name (last path segment) must be alphanumeric, "
                "underscore, or hyphen only.[/red]"
            )
            console.print(
                "[dim]Use a path whose folder name has no dots or spaces, e.g. /home/user/web3_2/aqua[/dim]"
            )
            return False

        try:
            from cai.repl.commands.config import set_env_var
        except ImportError:
            def set_env_var(k: str, v: str) -> bool:
                os.environ[k] = v
                return True

        set_env_var("CAI_WORKSPACE_DIR", os.path.dirname(path))
        set_env_var("CAI_WORKSPACE", workspace_name)

        target_agent = os.getenv("CAI_HUNT_AGENT", DEFAULT_HUNT_AGENT).strip() or DEFAULT_HUNT_AGENT
        agent_ok = handle_command("/agent", ["select", target_agent])
        auto_start = _is_truthy(os.getenv("CAI_HUNT_AUTO_START"), default=True)
        if auto_start:
            os.environ["CAI_HUNT_AUTO_PROMPT"] = _build_hunt_kickoff_prompt(path)
        else:
            os.environ.pop("CAI_HUNT_AUTO_PROMPT", None)
        # region agent log
        _debug_log(
            hypothesis_id="H2",
            location="src/cai/repl/commands/hunt.py:handle",
            message="/hunt workspace and agent selection result",
            data={
                "path": path,
                "workspace_dir": os.getenv("CAI_WORKSPACE_DIR"),
                "workspace": os.getenv("CAI_WORKSPACE"),
                "agent_selected": bool(agent_ok),
                "target_agent": target_agent,
                "auto_start": auto_start,
            },
        )
        # endregion
        # region agent log
        _debug_log(
            hypothesis_id="H5",
            location="src/cai/repl/commands/hunt.py:handle",
            message="/hunt auto kickoff prompt queued",
            data={
                "auto_prompt_set": bool(os.getenv("CAI_HUNT_AUTO_PROMPT", "").strip()),
                "target_agent": target_agent,
            },
        )
        # endregion

        console.print(
            Panel(
                f"Workspace: [bold green]{path}[/bold green]\n"
                f"Agent: [bold]{target_agent}[/bold]\n"
                f"Auto-start: [bold]{'enabled' if auto_start else 'disabled'}[/bold]\n\n"
                "Mode: [bold cyan]interactive[/bold cyan]\n"
                "Suggested: run discovery and candidate generation first, then move high-signal candidates through Judge Gate.\n\n"
                "For deterministic verification, run EliteWeb3Pipeline via Python adapter.",
                title="Web3 hunt ready",
                border_style="green",
            )
        )
        if not agent_ok:
            console.print(
                f"[yellow]Workspace was set; agent switch failed. Try /agent select {target_agent}[/yellow]"
            )
        return True

    def _handle_plugins(self, args: List[str]) -> bool:
        if not args:
            console.print(Panel(HUNT_PLUGINS_USAGE, title="Web3 Plugins", border_style="cyan"))
            return True

        subcommand = args[0].strip().lower()

        if subcommand == "list":
            response = list_plugins(ExposureSurface.AGENT)
            console.print_json(data=response)
            return True

        if subcommand == "describe":
            if len(args) < 2:
                console.print("[red]Usage: /hunt plugins describe <plugin_name>[/red]")
                return False
            plugin_name = args[1].strip()
            response = describe_plugin(plugin_name)
            console.print_json(data=response)
            return True

        if subcommand == "run":
            return self._handle_plugins_run(args[1:] if len(args) > 1 else [])

        console.print(f"[red]Unknown plugins subcommand: {subcommand}[/red]")
        console.print(Panel(HUNT_PLUGINS_USAGE, title="Web3 Plugins", border_style="yellow"))
        return False

    def _handle_plugins_run(self, args: List[str]) -> bool:
        if not args:
            console.print("[red]Usage: /hunt plugins run <plugin_name> [options][/red]")
            return False

        plugin_name = args[0].strip()
        parsed_args = {}
        policy_level = "safe"
        allow_aggressive = False
        dry_run = False
        timeout_sec = 30

        idx = 1
        while idx < len(args):
            token = args[idx]
            if token == "--args":
                if idx + 1 >= len(args):
                    console.print("[red]--args requires a JSON payload[/red]")
                    return False
                try:
                    value = json.loads(args[idx + 1])
                    parsed_args = value if isinstance(value, dict) else {"value": value}
                except Exception as exc:  # pylint: disable=broad-except
                    console.print(f"[red]Invalid JSON in --args: {exc}[/red]")
                    return False
                idx += 2
                continue
            if token == "--args-file":
                if idx + 1 >= len(args):
                    console.print("[red]--args-file requires a file path[/red]")
                    return False
                file_path = Path(args[idx + 1]).expanduser()
                if not file_path.exists():
                    console.print(f"[red]Args file not found: {file_path}[/red]")
                    return False
                try:
                    value = json.loads(file_path.read_text(encoding="utf-8"))
                    parsed_args = value if isinstance(value, dict) else {"value": value}
                except Exception as exc:  # pylint: disable=broad-except
                    console.print(f"[red]Invalid JSON in --args-file: {exc}[/red]")
                    return False
                idx += 2
                continue
            if token == "--policy":
                if idx + 1 >= len(args):
                    console.print("[red]--policy requires one of: safe|balanced|aggressive[/red]")
                    return False
                policy_level = args[idx + 1].strip().lower()
                idx += 2
                continue
            if token == "--allow-aggressive":
                allow_aggressive = True
                idx += 1
                continue
            if token == "--dry-run":
                dry_run = True
                idx += 1
                continue
            if token == "--timeout":
                if idx + 1 >= len(args):
                    console.print("[red]--timeout requires an integer value[/red]")
                    return False
                try:
                    timeout_sec = int(args[idx + 1])
                except ValueError:
                    console.print("[red]--timeout requires an integer value[/red]")
                    return False
                idx += 2
                continue

            console.print(f"[yellow]Ignoring unknown option: {token}[/yellow]")
            idx += 1

        try:
            request = PluginRunRequest(
                plugin_name=plugin_name,
                args=parsed_args,
                policy_level=parse_policy_level(policy_level),
                allow_aggressive=allow_aggressive,
                dry_run=dry_run,
                timeout_sec=timeout_sec,
                exposure_surface=ExposureSurface.AGENT,
            )
            response = run_plugin(request)
            console.print_json(data=response)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[red]Plugin execution failed: {exc}[/red]")
            return False


register_command(HuntCommand())
