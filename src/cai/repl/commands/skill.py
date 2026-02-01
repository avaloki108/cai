"""
Skill command for CAI REPL.

This module provides commands for managing CAI skills:
- /skill list - List all available skills
- /skill enable <name> - Enable a skill
- /skill disable <name> - Disable a skill
- /skill show <name> - Show skill details
- /skill reload - Reload skills from disk
"""

from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from cai.repl.commands.base import Command, register_command

console = Console()


class SkillCommand(Command):
    """Command for managing CAI skills."""

    def __init__(self):
        """Initialize the skill command."""
        super().__init__(
            name="/skill",
            description="Manage CAI skills (Claude Code/Codex-style)",
            aliases=["/skills", "/sk"],
        )
        self.add_subcommand("list", "List all available skills", self.handle_list)
        self.add_subcommand("enable", "Enable a skill", self.handle_enable)
        self.add_subcommand("disable", "Disable a skill", self.handle_disable)
        self.add_subcommand("show", "Show skill details", self.handle_show)
        self.add_subcommand("reload", "Reload skills from disk", self.handle_reload)
        self.add_subcommand("path", "Show skill search paths", self.handle_path)

    def handle_no_args(self) -> bool:
        """Show help when no args provided."""
        return self.handle_list(None)

    def handle_list(self, args: Optional[List[str]] = None) -> bool:
        """List all available skills."""
        try:
            from cai.skills import get_skill_registry, discover_skills

            registry = get_skill_registry()

            # Ensure skills are discovered
            if not registry.list_skills():
                discover_skills()

            skills = registry.list_skills()

            if not skills:
                console.print(
                    "[yellow]No skills found. Create skills in ~/.cai/skills/ or .cai/skills/[/yellow]"
                )
                console.print("\n[dim]Skill format: Create a directory with a SKILL.md file[/dim]")
                console.print("[dim]Example: ~/.cai/skills/my-skill/SKILL.md[/dim]")
                return True

            table = Table(
                title="Available Skills",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Source", style="blue")
            table.add_column("Description", style="white", max_width=50)

            for skill in sorted(skills, key=lambda s: s.name):
                status = "[green]✓ enabled[/green]" if registry.is_enabled(skill.name) else "[red]✗ disabled[/red]"
                table.add_row(
                    skill.name,
                    status,
                    skill.source,
                    skill.description[:50] + "..." if len(skill.description) > 50 else skill.description,
                )

            console.print(table)
            console.print(f"\n[dim]Total: {len(skills)} skills[/dim]")
            return True

        except Exception as e:
            console.print(f"[red]Error listing skills: {e}[/red]")
            return False

    def handle_enable(self, args: Optional[List[str]] = None) -> bool:
        """Enable a skill."""
        if not args:
            console.print("[yellow]Usage: /skill enable <skill-name>[/yellow]")
            return False

        try:
            from cai.skills import get_skill_registry

            registry = get_skill_registry()
            skill_name = args[0]

            if registry.enable(skill_name):
                console.print(f"[green]✓ Enabled skill: {skill_name}[/green]")
                return True
            else:
                console.print(f"[red]Skill not found: {skill_name}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Error enabling skill: {e}[/red]")
            return False

    def handle_disable(self, args: Optional[List[str]] = None) -> bool:
        """Disable a skill."""
        if not args:
            console.print("[yellow]Usage: /skill disable <skill-name>[/yellow]")
            return False

        try:
            from cai.skills import get_skill_registry

            registry = get_skill_registry()
            skill_name = args[0]

            if registry.disable(skill_name):
                console.print(f"[yellow]✗ Disabled skill: {skill_name}[/yellow]")
                return True
            else:
                console.print(f"[red]Skill not found: {skill_name}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Error disabling skill: {e}[/red]")
            return False

    def handle_show(self, args: Optional[List[str]] = None) -> bool:
        """Show skill details."""
        if not args:
            console.print("[yellow]Usage: /skill show <skill-name>[/yellow]")
            return False

        try:
            from cai.skills import get_skill_registry

            registry = get_skill_registry()
            skill_name = args[0]
            skill = registry.get(skill_name)

            if not skill:
                console.print(f"[red]Skill not found: {skill_name}[/red]")
                return False

            # Show skill metadata
            console.print(Panel(
                f"[bold cyan]{skill.name}[/bold cyan]\n\n"
                f"[bold]Description:[/bold] {skill.description}\n"
                f"[bold]Source:[/bold] {skill.source}\n"
                f"[bold]Path:[/bold] {skill.path}\n"
                f"[bold]Tags:[/bold] {', '.join(skill.tags) if skill.tags else 'None'}\n"
                f"[bold]Agents:[/bold] {', '.join(skill.agents) if skill.agents else 'All agents'}\n"
                f"[bold]Always Apply:[/bold] {skill.always_apply}\n"
                f"[bold]Status:[/bold] {'Enabled' if registry.is_enabled(skill.name) else 'Disabled'}",
                title="Skill Details",
                border_style="blue",
            ))

            # Show skill content preview
            content_preview = skill.content[:1000]
            if len(skill.content) > 1000:
                content_preview += "\n\n[dim]... (truncated, use /skill read for full content)[/dim]"

            console.print(Panel(
                Markdown(content_preview),
                title="Content Preview",
                border_style="green",
            ))

            return True

        except Exception as e:
            console.print(f"[red]Error showing skill: {e}[/red]")
            return False

    def handle_reload(self, args: Optional[List[str]] = None) -> bool:
        """Reload skills from disk."""
        try:
            from cai.skills import discover_skills, get_skill_registry
            from cai.skills.registry import reset_skill_registry

            # Reset and rediscover
            reset_skill_registry()
            skills = discover_skills()

            console.print(f"[green]✓ Reloaded {len(skills)} skills[/green]")
            return True

        except Exception as e:
            console.print(f"[red]Error reloading skills: {e}[/red]")
            return False

    def handle_path(self, args: Optional[List[str]] = None) -> bool:
        """Show skill search paths."""
        import os

        paths = [
            ("Built-in", Path(__file__).parent.parent.parent / "skills" / "builtin"),
            ("Claude Code", Path.home() / ".claude" / "skills"),
            ("Cursor", Path.home() / ".cursor" / "skills-cursor"),
            ("Cursor Nightly", Path.home() / ".cursor-nightly" / "skills-cursor"),
            ("User (CAI)", Path.home() / ".cai" / "skills"),
            ("Project", Path.cwd() / ".cai" / "skills"),
        ]

        extra_paths = os.getenv("CAI_SKILLS_PATH", "")
        if extra_paths:
            for p in extra_paths.split(":"):
                paths.append(("Extra (CAI_SKILLS_PATH)", Path(p.strip())))

        table = Table(
            title="Skill Search Paths",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Type", style="cyan")
        table.add_column("Path", style="white")
        table.add_column("Exists", style="green")

        for path_type, path in paths:
            exists = "[green]✓[/green]" if path.exists() else "[red]✗[/red]"
            table.add_row(path_type, str(path), exists)

        console.print(table)
        return True


# Register the command
register_command(SkillCommand())
