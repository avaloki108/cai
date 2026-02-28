"""
Hunt command for CAI REPL.
Quickstart for web3 project audit / bug bounty: set workspace to a path and switch to web3_bug_bounty_agent.
Backed by an apex-style pipeline: Pre-flight → Static → Economic → Fuzz → Exploit → Report.
"""
import os
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel

from cai.repl.commands.base import Command, handle_command, register_command

console = Console()

HUNT_NO_ARGS_PANEL = """[bold]Web3 Hunt[/bold] — Master audit quickstart. Sets workspace to a repo and switches to [cyan]web3_bug_bounty_agent[/cyan].

[bold]Pipeline[/bold]: Pre-flight (intel, build, recon) → [Stage 1] Static → [Stage 2] Economic → [Stage 3] Fuzz → [Stage 4] Exploit → Validation → Report.

[bold yellow]Usage[/bold yellow]
  [green]/hunt <location>[/green]   Path to the web3 project (absolute or relative)

[bold cyan]Examples[/bold cyan]
  [green]/hunt /home/user/web3_2/aqua[/green]
  [green]/hunt ./my-contracts[/green]

After running [green]/hunt <path>[/green], ask to audit the repo, run static analysis, or describe the protocol. Quality bar: attacker-exploitable only; clear attack path and impact."""


class HuntCommand(Command):
    """Command for web3 audit quickstart: set workspace to <location> and switch to web3 bug bounty agent."""

    def __init__(self):
        super().__init__(
            name="/hunt",
            description="Web3 audit quickstart: set workspace to <location> and switch to web3 bug bounty agent.",
            aliases=[],
        )

    def handle(self, args: Optional[List[str]] = None) -> bool:
        if not args or len(args) < 1:
            console.print(Panel(HUNT_NO_ARGS_PANEL, title="Web3 Hunt — Quick Start", border_style="cyan"))
            return True

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

        agent_ok = handle_command("/agent", ["select", "web3_bug_bounty_agent"])

        console.print(
            Panel(
                f"Workspace: [bold green]{path}[/bold green]\n"
                f"Agent: [bold]web3_bug_bounty_agent[/bold]\n\n"
                "Suggested: ask to run a full audit (pre-flight → static → economic → fuzz → exploit) or to describe the repo and scope.",
                title="Web3 hunt ready",
                border_style="green",
            )
        )
        if not agent_ok:
            console.print(
                "[yellow]Workspace was set; agent switch failed. Try /agent select web3_bug_bounty_agent[/yellow]"
            )
        return True


register_command(HuntCommand())
