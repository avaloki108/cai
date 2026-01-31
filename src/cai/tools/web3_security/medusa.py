"""
Medusa fuzzing framework for Ethereum smart contracts.
Medusa is a parallelized, coverage-guided fuzzer for Solidity smart contracts
with support for property testing and assertion checking.
"""

import os
from typing import Optional
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import MEDUSA_PATH


@function_tool
def medusa_fuzz(
    project_dir: str,
    config: Optional[str] = None,
    compilation_target: Optional[str] = None,
    workers: int = 10,
    timeout: int = 0,
    test_limit: int = 0,
    seq_len: int = 100,
    target_contracts: Optional[str] = None,
    corpus_dir: Optional[str] = None,
    fail_fast: bool = False,
    explore: bool = False,
    use_slither: bool = False,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Medusa fuzzing on Solidity smart contracts.

    Medusa is a modern, parallelized fuzzer that uses coverage-guided fuzzing
    to discover vulnerabilities and invariant violations. It supports property
    testing, assertion testing, and optimization testing.

    Args:
        project_dir: Path to project directory (must contain medusa.json or be Foundry/Hardhat project)
                    This is where medusa will run from (working directory).
        config: Path to medusa.json configuration file (optional, auto-detected)
        compilation_target: Path to contract file or directory to compile (optional)
        workers: Number of parallel fuzzer workers (default: 10)
        timeout: Timeout in seconds, 0 = unlimited (default: 0)
        test_limit: Max transactions to test, 0 = unlimited (default: 0)
        seq_len: Maximum transactions in sequence (default: 100)
        target_contracts: Comma-separated list of contracts to fuzz
        corpus_dir: Directory for corpus and coverage reports
        fail_fast: Stop on first failed test
        explore: Enable exploration mode
        use_slither: Use Slither for additional analysis
        extra_args: Additional Medusa CLI arguments

    Returns:
        str: Medusa fuzzing results including findings, coverage, and statistics

    Examples:
        - Basic fuzzing: medusa_fuzz("./project")
        - With timeout: medusa_fuzz("./project", timeout=300, test_limit=10000)
        - Target specific contracts: medusa_fuzz("./project", target_contracts="Token,Vault")
    """
    # Validate project directory
    if not project_dir or not project_dir.strip():
        return "ERROR: project_dir is required."
    
    if not os.path.isdir(project_dir):
        return f"ERROR: Project directory does not exist: {project_dir}"

    cmd_parts = [MEDUSA_PATH, "fuzz"]

    if config:
        cmd_parts.append(f"--config {config}")

    if compilation_target:
        cmd_parts.append(f"--compilation-target {compilation_target}")

    cmd_parts.append(f"--workers {workers}")

    if timeout > 0:
        cmd_parts.append(f"--timeout {timeout}")

    if test_limit > 0:
        cmd_parts.append(f"--test-limit {test_limit}")

    cmd_parts.append(f"--seq-len {seq_len}")

    if target_contracts:
        cmd_parts.append(f"--target-contracts {target_contracts}")

    if corpus_dir:
        cmd_parts.append(f"--corpus-dir {corpus_dir}")

    if fail_fast:
        cmd_parts.append("--fail-fast")

    if explore:
        cmd_parts.append("--explore")

    if use_slither:
        cmd_parts.append("--use-slither")

    if extra_args:
        cmd_parts.append(extra_args)

    command = " ".join(cmd_parts)
    
    # Run from the project directory
    full_command = f"cd {project_dir} && {command}"
    return run_command(full_command, ctf=ctf, timeout=900)


@function_tool
def medusa_init(
    project_dir: str,
    platform: str = "",
    compilation_target: Optional[str] = None,
    output_file: Optional[str] = None,
    ctf=None
) -> str:
    """
    Initialize a new Medusa configuration file in a project.

    Creates a medusa.json configuration file with sensible defaults for the
    detected or specified platform (Foundry, Hardhat, etc.).

    Args:
        project_dir: Path to project directory where medusa.json will be created
        platform: Platform type (auto-detected if empty). Options: "crytic-compile"
        compilation_target: Target contract or directory to compile
        output_file: Output path for the config file (default: medusa.json in project_dir)

    Returns:
        str: Success message and configuration file path

    Examples:
        - Auto-detect platform: medusa_init("./my-foundry-project")
        - With specific target: medusa_init("./project", compilation_target="src/Token.sol")
        - Custom output: medusa_init("./project", output_file="custom-medusa.json")
    """
    # Validate project directory
    if not project_dir or not project_dir.strip():
        return "ERROR: project_dir is required."
    
    if not os.path.isdir(project_dir):
        return f"ERROR: Project directory does not exist: {project_dir}"

    cmd_parts = [MEDUSA_PATH, "init"]

    # Platform is a positional argument
    if platform:
        cmd_parts.append(platform)

    if compilation_target:
        cmd_parts.append(f"--compilation-target {compilation_target}")

    if output_file:
        cmd_parts.append(f"--out {output_file}")

    command = " ".join(cmd_parts)
    
    # Run from the project directory
    full_command = f"cd {project_dir} && {command}"
    return run_command(full_command, ctf=ctf)


@function_tool
def medusa_test(
    project_dir: str,
    target_contracts: Optional[str] = None,
    config: Optional[str] = None,
    timeout: int = 300,
    test_limit: int = 10000,
    fail_fast: bool = True,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Medusa tests with sensible defaults for quick testing.

    This is a convenience wrapper around medusa_fuzz with defaults
    suitable for running property tests quickly.

    Args:
        project_dir: Path to project directory
        target_contracts: Comma-separated list of contracts to test
        config: Path to medusa.json configuration file
        timeout: Timeout in seconds (default: 300 = 5 minutes)
        test_limit: Max transactions to test (default: 10000)
        fail_fast: Stop on first failed test (default: True)
        extra_args: Additional arguments

    Returns:
        str: Test execution results
    """
    return medusa_fuzz(
        project_dir=project_dir,
        config=config,
        target_contracts=target_contracts,
        timeout=timeout,
        test_limit=test_limit,
        fail_fast=fail_fast,
        extra_args=extra_args,
        ctf=ctf
    )
