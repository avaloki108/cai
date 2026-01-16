"""
Scribble specification instrumentation for Solidity smart contracts.
This wrapper lets the agent run Scribble with arbitrary flags so users can
add runtime assertions to contracts before testing or fuzzing.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SCRIBBLE_PATH


@function_tool
def scribble_run(target: str, args: str = "", ctf=None) -> str:
    """
    Run Scribble to instrument Solidity contracts with specification checks.

    Args:
        target: Path to a Solidity file or project directory.
        args: Additional Scribble CLI flags (e.g., "--output-mode files --output-dir ./scribble-out").

    Returns:
        str: Scribble CLI output (instrumented files are written to the specified output location).
    """
    command = f"{SCRIBBLE_PATH} {args} {target}"
    return run_command(command, ctf=ctf)
