"""
Oyente Plus - Symbolic Execution Tool for Ethereum Smart Contracts

Oyente Plus performs symbolic execution to detect vulnerabilities like
reentrancy, integer overflow/underflow, and other security issues.
"""

from typing import Optional
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import OYENTE_PLUS_PATH


@function_tool
def oyente_analyze(
    source: str,
    target_contracts: Optional[str] = None,
    timeout: int = 10000,
    gas_limit: int = 300000,
    loop_limit: int = 10,
    depth_limit: int = 50,
    global_timeout: int = 300,
    json_output: bool = False,
    report: bool = False,
    verbose: bool = False,
    assertion: bool = False,
    parallel: bool = False,
    bytecode: bool = False,
    remap: Optional[str] = None,
    allow_paths: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Oyente Plus symbolic execution analysis on smart contracts.

    Oyente uses Z3 SMT solver for symbolic execution to detect vulnerabilities
    including reentrancy, integer issues, and assertion failures.

    Args:
        source: Path to Solidity file or bytecode. Use "-" for stdin.
        target_contracts: Space-separated list of contract names to analyze
                         (default: all contracts in file)
        timeout: Timeout for Z3 solver in milliseconds (default: 10000)
        gas_limit: Gas limit for execution (default: 300000)
        loop_limit: Maximum loop iterations (default: 10)
        depth_limit: Maximum DFS depth (default: 50)
        global_timeout: Total analysis timeout in seconds (default: 300)
        json_output: Output results as JSON
        report: Create detailed .report file
        verbose: Enable verbose output with all details
        assertion: Check assertion failures (assert statements)
        parallel: Run analysis in parallel (performance varies by contract)
        bytecode: Treat source as bytecode instead of Solidity
        remap: Directory path remappings for imports
        allow_paths: Allowed paths for Solidity imports
        extra_args: Additional Oyente arguments

    Returns:
        str: Symbolic execution results with detected vulnerabilities

    Detected Vulnerabilities:
        - Reentrancy
        - Integer overflow/underflow
        - Timestamp dependence
        - Assertion failures
        - Callstack depth attack
        - Parity multisig bug

    Examples:
        oyente_analyze("contract.sol", assertion=True, json_output=True)
        oyente_analyze("bytecode.bin", bytecode=True, timeout=20000)
    """
    args = [f"-s {source}"]

    if target_contracts:
        args.append(f"-cnames {target_contracts}")

    args.append(f"-t {timeout}")
    args.append(f"-gl {gas_limit}")
    args.append(f"-ll {loop_limit}")
    args.append(f"-dl {depth_limit}")
    args.append(f"-glt {global_timeout}")

    if json_output:
        args.append("-j")

    if report:
        args.append("-r")

    if verbose:
        args.append("-v")

    if assertion:
        args.append("-a")

    if parallel:
        args.append("-pl")

    if bytecode:
        args.append("-b")

    if remap:
        args.append(f"-rmp {remap}")

    if allow_paths:
        args.append(f"-ap {allow_paths}")

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_analyze_remote(
    url: str,
    timeout: int = 10000,
    json_output: bool = False,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze a contract from a remote URL.

    Args:
        url: URL to fetch contract source from
        timeout: Z3 solver timeout in milliseconds
        json_output: Output results as JSON
        extra_args: Additional arguments

    Returns:
        str: Analysis results for remote contract
    """
    args = [f"-ru {url}", f"-t {timeout}"]

    if json_output:
        args.append("-j")

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_check_vulnerability(
    source: str,
    vuln_type: str,
    timeout: int = 10000,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Check for specific vulnerability types using Oyente.

    Args:
        source: Path to Solidity file
        vuln_type: Vulnerability type to check:
                  - "reentrancy": Check for reentrancy vulnerabilities
                  - "overflow": Check for integer overflow
                  - "underflow": Check for integer underflow
                  - "timestamp": Check for timestamp dependence
                  - "assertion": Check for assertion failures
        timeout: Z3 solver timeout
        extra_args: Additional arguments

    Returns:
        str: Targeted vulnerability analysis results
    """
    vuln_flags = {
        "reentrancy": "",  # Default check
        "overflow": "",    # Default check
        "underflow": "",   # Default check
        "timestamp": "",   # Default check
        "assertion": "-a",
    }

    args = [f"-s {source}", f"-t {timeout}"]

    vuln_flag = vuln_flags.get(vuln_type, "")
    if vuln_flag:
        args.append(vuln_flag)

    args.append("-j")  # JSON for easier parsing

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_generate_tests(
    source: str,
    output_dir: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Generate test cases for each branch of the symbolic execution tree.

    Creates concrete test inputs that exercise different code paths,
    useful for improving test coverage.

    Args:
        source: Path to Solidity file
        output_dir: Directory to save generated tests
        extra_args: Additional arguments

    Returns:
        str: Generated test cases for symbolic execution branches
    """
    args = [f"-s {source}", "-gtc"]  # generate-test-cases flag

    if output_dir:
        args.append(f"-rp {output_dir}")

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_with_state(
    source: str,
    state_file: str = "state.json",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Analyze contract starting from a specific state.

    Load initial state from a JSON file to analyze contract behavior
    from a particular starting point.

    Args:
        source: Path to Solidity file
        state_file: Path to state.json file with initial state
        extra_args: Additional arguments

    Returns:
        str: Analysis results from specified initial state
    """
    args = [f"-s {source}", "-st"]  # state flag

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_print_paths(
    source: str,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Print path condition information for all execution paths.

    Shows the symbolic constraints for each explored path, useful for
    understanding how the solver reaches different code branches.

    Args:
        source: Path to Solidity file
        extra_args: Additional arguments

    Returns:
        str: Path conditions for all symbolic execution paths
    """
    args = [f"-s {source}", "-p"]  # paths flag

    if extra_args:
        args.append(extra_args)

    command = f"{OYENTE_PLUS_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def oyente_compare_contracts(
    contract1: str,
    contract2: str,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Compare two contracts for behavioral differences using symbolic execution.

    Useful for verifying that an upgrade or optimization maintains
    the same behavior as the original.

    Args:
        contract1: Path to first contract
        contract2: Path to second contract
        extra_args: Additional arguments

    Returns:
        str: Comparison results showing behavioral differences
    """
    # Run analysis on both and compare
    results = []

    results.append("=" * 60)
    results.append("CONTRACT 1 ANALYSIS")
    results.append("=" * 60)
    cmd1 = f"{OYENTE_PLUS_PATH} -s {contract1} -j"
    result1 = run_command(cmd1, ctf=ctf)
    results.append(result1)

    results.append("\n" + "=" * 60)
    results.append("CONTRACT 2 ANALYSIS")
    results.append("=" * 60)
    cmd2 = f"{OYENTE_PLUS_PATH} -s {contract2} -j"
    result2 = run_command(cmd2, ctf=ctf)
    results.append(result2)

    results.append("\n" + "=" * 60)
    results.append("COMPARISON SUMMARY")
    results.append("=" * 60)
    results.append("Review the analyses above to identify behavioral differences.")

    return "\n".join(results)
