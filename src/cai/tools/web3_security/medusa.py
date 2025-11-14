"""
Medusa fuzzing framework for Ethereum smart contracts.
Medusa is a parallelized, coverage-guided fuzzer for Solidity smart contracts
with support for property testing and assertion checking.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import MEDUSA_PATH


@function_tool
def medusa_fuzz(target: str, args: str = "", ctf=None) -> str:
    """
    Run Medusa fuzzing on Solidity smart contracts.

    Medusa is a modern, parallelized fuzzer that uses coverage-guided fuzzing
    to discover vulnerabilities and invariant violations. It supports property
    testing, assertion testing, and optimization testing.

    Args:
        target: Path to project directory (must contain medusa.json config or be a Foundry/Hardhat project)
        args: Additional Medusa arguments
              Common options:
              - --config <file>: Path to medusa.json configuration file
              - --compilation-target <path>: Compilation target (auto-detected for Foundry/Hardhat)
              - --test-limit <n>: Number of transactions to test (default: 0 = unlimited)
              - --timeout <sec>: Timeout for fuzzing campaign (default: 0 = unlimited)
              - --workers <n>: Number of parallel workers (default: 10)
              - --target-contracts <names>: Comma-separated list of contracts to test
              - --target-functions <names>: Comma-separated list of functions to call
              - --seq-len <n>: Sequence length for transaction chains
              - --corpus-dir <dir>: Directory for corpus storage
              - --coverage-reports: Generate coverage reports

    Returns:
        str: Medusa fuzzing results including findings, coverage, and statistics

    Examples:
        - Basic fuzzing: medusa_fuzz("./project")
        - With config: medusa_fuzz("./project", "--config custom-medusa.json")
        - Limited run: medusa_fuzz("./project", "--test-limit 10000 --timeout 300")
        - Parallel fuzzing: medusa_fuzz("./project", "--workers 20 --coverage-reports")
    """
    command = f'{MEDUSA_PATH} fuzz --target {target} {args}'
    return run_command(command, ctf=ctf, timeout=900)  # Extended timeout for fuzzing


@function_tool
def medusa_init(project_dir: str, args: str = "", ctf=None) -> str:
    """
    Initialize a new Medusa configuration file in a project.

    Args:
        project_dir: Path to project directory
        args: Additional arguments (e.g., "--out medusa.json")

    Returns:
        str: Success message and configuration file path
    """
    command = f'{MEDUSA_PATH} init --target {project_dir} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def medusa_test(target: str, test_name: str = "", args: str = "", ctf=None) -> str:
    """
    Run specific Medusa tests on smart contracts.

    Args:
        target: Path to project directory
        test_name: Specific test function or contract to run (optional)
        args: Additional test arguments

    Returns:
        str: Test execution results
    """
    test_arg = f"--test {test_name}" if test_name else ""
    command = f'{MEDUSA_PATH} fuzz --target {target} {test_arg} {args}'
    return run_command(command, ctf=ctf, timeout=600)
