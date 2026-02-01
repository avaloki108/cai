"""CLI preflight checks and standard flag handling."""

from __future__ import annotations

import os
import sys
from typing import Dict, List

from wasabi import color

from cai.sdk.agents.version import __version__
from cai.tools.web3_security.config import get_available_tools


def _print_help() -> None:
    print(
        "\n".join(
            [
                "CAI CLI",
                "",
                "Usage:",
                "  cai [prompt]",
                "",
                "Standard flags:",
                "  --help, -h     Show this help message",
                "  --version      Show version information",
                "  --setup        Run setup guidance and preflight checks",
                "  --verify       Run preflight validation and report tool status",
                "",
            ]
        )
    )


def _print_version() -> None:
    print(f"CAI version: {__version__}")


def _preflight_checks() -> Dict[str, object]:
    tools = get_available_tools()
    missing_tools = [name for name, ok in tools.items() if not ok]
    model = os.getenv("CAI_MODEL", "")
    agent_type = os.getenv("CAI_AGENT_TYPE", "")

    issues: List[str] = []
    if not model:
        issues.append("CAI_MODEL is not set")
    if not agent_type:
        issues.append("CAI_AGENT_TYPE is not set (default will be used)")
    if missing_tools:
        issues.append(f"Missing tools: {', '.join(missing_tools)}")

    return {
        "ok": len(issues) == 0,
        "issues": issues,
        "missing_tools": missing_tools,
        "tools": tools,
        "model": model,
        "agent_type": agent_type,
    }


def _print_preflight_report(report: Dict[str, object]) -> None:
    if report.get("ok"):
        print(color("Preflight OK: all required checks passed.", fg="green"))
    else:
        print(color("Preflight warnings detected:", fg="yellow"))
        for issue in report.get("issues", []):
            print(f"- {issue}")

    tools = report.get("tools", {})
    if tools:
        print("\nTool availability:")
        for tool_name, ok in tools.items():
            status = "OK" if ok else "MISSING"
            color_name = "green" if ok else "red"
            print(f"  - {tool_name}: {color(status, fg=color_name)}")


def handle_standard_flags(argv: List[str]) -> bool:
    """Handle standard CLI flags. Returns True if execution should stop."""
    if "--help" in argv or "-h" in argv:
        _print_help()
        return True
    if "--version" in argv:
        _print_version()
        return True
    if "--setup" in argv:
        report = _preflight_checks()
        _print_preflight_report(report)
        if report.get("missing_tools"):
            print(
                color(
                    "Install missing tools or set WEB3_*_PATH env vars to continue.",
                    fg="yellow",
                )
            )
        return True
    if "--verify" in argv:
        report = _preflight_checks()
        _print_preflight_report(report)
        return True
    return False


def extract_initial_prompt(argv: List[str]) -> str | None:
    """Return the first non-flag argument as the initial prompt."""
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        return arg
    return None
