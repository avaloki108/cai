"""
Foundry - Smart Contract Development and Testing Framework

Foundry is a blazing fast, portable and modular toolkit for Ethereum
application development written in Rust.

Components:
- Forge: Testing framework
- Cast: Swiss army knife for interacting with EVM smart contracts
- Anvil: Local testnet node

Supported Languages: Solidity
"""

from typing import Optional, Union
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import FORGE_PATH, CAST_PATH, ANVIL_PATH


# ============================================================================
# Forge - Testing Framework
# ============================================================================

@function_tool
def forge_test(
    project_dir: str,
    match_test: Optional[str] = None,
    match_contract: Optional[str] = None,
    match_path: Optional[str] = None,
    fork_url: Optional[str] = None,
    fork_block: Optional[Union[int, str]] = None,
    verbosity: Union[int, str] = 2,
    gas_report: bool = False,
    fuzz_runs: Optional[Union[int, str]] = 256,
    args: str = "",
    ctf=None
) -> str:
    """
    Run Foundry tests on smart contracts.

    Args:
        project_dir: Path to Foundry project directory
        match_test: Only run tests matching this regex pattern
        match_contract: Only run tests in contracts matching this regex
        match_path: Only run tests in paths matching this regex
        fork_url: RPC URL to fork from for testing
        fork_block: Block number to fork from
        verbosity: Verbosity level (0-5, default: 2)
        gas_report: Generate gas report
        fuzz_runs: Number of fuzz runs (default: 256)
        args: Additional forge arguments

    Returns:
        str: Test results including pass/fail status and gas usage

    Examples:
        - Run all tests: forge_test("./project")
        - Specific test: forge_test("./project", match_test="testTransfer")
        - Fork testing: forge_test("./project", fork_url="https://eth-mainnet.g.alchemy.com/v2/...")
    """
    # Handle string "null" from JSON parsing - convert to None
    if isinstance(fork_block, str):
        if fork_block.lower() == "null" or fork_block.strip() == "":
            fork_block = None
        else:
            try:
                fork_block = int(fork_block)
            except ValueError:
                return f"ERROR: fork_block must be an integer, got: {fork_block}"
    
    if isinstance(fork_url, str) and (fork_url.lower() == "null" or fork_url.strip() == ""):
        fork_url = None
    
    if isinstance(match_test, str) and (match_test.lower() == "null" or match_test.strip() == ""):
        match_test = None
    
    if isinstance(match_contract, str) and (match_contract.lower() == "null" or match_contract.strip() == ""):
        match_contract = None

    if isinstance(match_path, str) and (match_path.lower() == "null" or match_path.strip() == ""):
        match_path = None

    if isinstance(verbosity, str):
        if verbosity.lower() == "null" or verbosity.strip() == "":
            verbosity = 2
        else:
            try:
                verbosity = int(verbosity)
            except ValueError:
                return f"ERROR: verbosity must be an integer, got: {verbosity}"

    if isinstance(fuzz_runs, str):
        if fuzz_runs.lower() == "null" or fuzz_runs.strip() == "":
            fuzz_runs = None
        else:
            try:
                fuzz_runs = int(fuzz_runs)
            except ValueError:
                return f"ERROR: fuzz_runs must be an integer, got: {fuzz_runs}"

    cmd_parts = [f"cd {project_dir} &&", FORGE_PATH, "test"]

    if match_test:
        cmd_parts.append(f"--match-test {match_test}")

    if match_contract:
        cmd_parts.append(f"--match-contract {match_contract}")

    if match_path:
        cmd_parts.append(f"--match-path {match_path}")

    if fork_url:
        cmd_parts.append(f"--fork-url {fork_url}")

    if fork_block:
        cmd_parts.append(f"--fork-block-number {fork_block}")

    cmd_parts.append(f"-{'v' * verbosity}")

    if gas_report:
        cmd_parts.append("--gas-report")

    if fuzz_runs is not None:
        cmd_parts.append(f"--fuzz-runs {fuzz_runs}")

    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf, timeout=600)


@function_tool
def forge_build(
    project_dir: str,
    optimizer: bool = True,
    optimizer_runs: int = 200,
    args: str = "",
    ctf=None
) -> str:
    """
    Build/compile a Foundry project.

    Args:
        project_dir: Path to Foundry project directory
        optimizer: Enable optimizer (default: True)
        optimizer_runs: Number of optimizer runs (default: 200)
        args: Additional forge arguments

    Returns:
        str: Build output including any compilation errors
    """
    import os
    
    # Check if foundry.toml exists in the project directory
    foundry_toml = os.path.join(project_dir, "foundry.toml")
    if not os.path.exists(foundry_toml):
        # Try to find foundry.toml files in subdirectories
        import subprocess
        try:
            result = subprocess.run(
                ["find", project_dir, "-name", "foundry.toml", "-type", "f"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                foundry_dirs = [os.path.dirname(p) for p in result.stdout.strip().split('\n')]
                dirs_list = '\n  - '.join(foundry_dirs[:5])  # Show first 5
                if len(foundry_dirs) > 5:
                    dirs_list += f'\n  ... and {len(foundry_dirs) - 5} more'
                return f"ERROR: No foundry.toml found in {project_dir}\n\nFound Foundry projects in subdirectories:\n  - {dirs_list}\n\nPlease specify one of these directories, or create a foundry.toml in the root directory."
        except Exception:
            pass
        
        return f"ERROR: No foundry.toml found in {project_dir}. This doesn't appear to be a Foundry project root.\n\nTip: Foundry projects require a foundry.toml file. Either:\n1. Specify a subdirectory that contains foundry.toml\n2. Create a foundry.toml in the root directory"
    
    cmd_parts = [f"cd {project_dir} &&", FORGE_PATH, "build"]

    if optimizer:
        cmd_parts.append(f"--optimizer-runs {optimizer_runs}")

    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    result = run_command(command, ctf=ctf)
    
    # If result says "Nothing to compile", provide helpful context
    if "Nothing to compile" in result:
        return f"{result}\n\nNOTE: This usually means:\n1. No Solidity files found in the src/ directory\n2. All contracts are already compiled and up-to-date\n3. The foundry.toml configuration may need adjustment\n\nCheck the foundry.toml src/lib paths and ensure .sol files exist."
    
    return result


@function_tool
def forge_coverage(
    project_dir: str,
    report_format: str = "summary",
    fork_url: Optional[str] = None,
    args: str = "",
    ctf=None
) -> str:
    """
    Generate code coverage report for Foundry tests.

    Args:
        project_dir: Path to Foundry project directory
        report_format: Coverage report format (summary, lcov, html)
        fork_url: RPC URL to fork from
        args: Additional arguments

    Returns:
        str: Coverage report
    """
    cmd_parts = [f"cd {project_dir} &&", FORGE_PATH, "coverage"]

    cmd_parts.append(f"--report {report_format}")

    if fork_url:
        cmd_parts.append(f"--fork-url {fork_url}")

    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf, timeout=600)


@function_tool
def forge_inspect(
    project_dir: str,
    contract: str,
    field: str = "abi",
    ctf=None
) -> str:
    """
    Inspect contract artifacts.

    Args:
        project_dir: Path to Foundry project directory
        contract: Contract name to inspect
        field: Field to inspect (abi, bytecode, deployedBytecode, gasEstimates, etc.)

    Returns:
        str: Requested contract information
    """
    cmd_parts = [f"cd {project_dir} &&", FORGE_PATH, "inspect", contract, field]
    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def forge_snapshot(
    project_dir: str,
    match_test: Optional[str] = None,
    diff: bool = False,
    args: str = "",
    ctf=None
) -> str:
    """
    Create or compare gas snapshots.

    Args:
        project_dir: Path to Foundry project directory
        match_test: Only snapshot tests matching this pattern
        diff: Compare against existing snapshot
        args: Additional arguments

    Returns:
        str: Gas snapshot results
    """
    cmd_parts = [f"cd {project_dir} &&", FORGE_PATH, "snapshot"]

    if match_test:
        cmd_parts.append(f"--match-test {match_test}")

    if diff:
        cmd_parts.append("--diff")

    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf, timeout=600)


# ============================================================================
# Cast - EVM Swiss Army Knife
# ============================================================================

@function_tool
def cast_call(
    to: str,
    sig: str,
    args_list: str = "",
    rpc_url: Optional[str] = None,
    block: Optional[str] = None,
    ctf=None
) -> str:
    """
    Call a contract function without sending a transaction.

    Args:
        to: Contract address
        sig: Function signature (e.g., "balanceOf(address)")
        args_list: Function arguments (space-separated)
        rpc_url: RPC endpoint URL
        block: Block number or tag (latest, pending, etc.)

    Returns:
        str: Function return value

    Examples:
        cast_call("0x...", "balanceOf(address)", "0x...", rpc_url="https://eth-mainnet...")
    """
    cmd_parts = [CAST_PATH, "call", to, f'"{sig}"']

    if args_list:
        cmd_parts.append(args_list)

    if rpc_url:
        cmd_parts.append(f"--rpc-url {rpc_url}")

    if block:
        cmd_parts.append(f"--block {block}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cast_storage(
    address: str,
    slot: str,
    rpc_url: Optional[str] = None,
    block: Optional[str] = None,
    ctf=None
) -> str:
    """
    Read storage slot from a contract.

    Args:
        address: Contract address
        slot: Storage slot number (hex or decimal)
        rpc_url: RPC endpoint URL
        block: Block number or tag

    Returns:
        str: Storage value at the specified slot
    """
    cmd_parts = [CAST_PATH, "storage", address, slot]

    if rpc_url:
        cmd_parts.append(f"--rpc-url {rpc_url}")

    if block:
        cmd_parts.append(f"--block {block}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cast_code(
    address: str,
    rpc_url: Optional[str] = None,
    block: Optional[str] = None,
    ctf=None
) -> str:
    """
    Get the bytecode of a contract.

    Args:
        address: Contract address
        rpc_url: RPC endpoint URL
        block: Block number or tag

    Returns:
        str: Contract bytecode
    """
    cmd_parts = [CAST_PATH, "code", address]

    if rpc_url:
        cmd_parts.append(f"--rpc-url {rpc_url}")

    if block:
        cmd_parts.append(f"--block {block}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cast_abi_decode(
    sig: str,
    calldata: str,
    input_mode: bool = False,
    ctf=None
) -> str:
    """
    Decode ABI-encoded data.

    Args:
        sig: Function signature or tuple of types
        calldata: ABI-encoded data to decode
        input_mode: Decode as input data (includes function selector)

    Returns:
        str: Decoded values
    """
    cmd_parts = [CAST_PATH, "abi-decode"]

    if input_mode:
        cmd_parts.append("--input")

    cmd_parts.extend([f'"{sig}"', calldata])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cast_sig(
    signature: str,
    ctf=None
) -> str:
    """
    Get the function selector for a function signature.

    Args:
        signature: Function signature (e.g., "transfer(address,uint256)")

    Returns:
        str: 4-byte function selector
    """
    command = f'{CAST_PATH} sig "{signature}"'
    return run_command(command, ctf=ctf)


@function_tool
def cast_4byte(
    selector: str,
    ctf=None
) -> str:
    """
    Lookup function signatures for a 4-byte selector.

    Args:
        selector: 4-byte function selector (e.g., "0xa9059cbb")

    Returns:
        str: Matching function signatures from 4byte.directory
    """
    command = f"{CAST_PATH} 4byte {selector}"
    return run_command(command, ctf=ctf)


@function_tool
def cast_interface(
    address: str,
    rpc_url: Optional[str] = None,
    ctf=None
) -> str:
    """
    Generate a Solidity interface from a contract's ABI.

    Args:
        address: Contract address or path to ABI file
        rpc_url: RPC endpoint URL (for on-chain contracts)

    Returns:
        str: Generated Solidity interface
    """
    cmd_parts = [CAST_PATH, "interface", address]

    if rpc_url:
        cmd_parts.append(f"--rpc-url {rpc_url}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


# ============================================================================
# Anvil - Local Testnet Node
# ============================================================================

@function_tool
def anvil_start(
    fork_url: Optional[str] = None,
    fork_block: Optional[int] = None,
    port: int = 8545,
    accounts: int = 10,
    balance: int = 10000,
    args: str = "",
    ctf=None
) -> str:
    """
    Start a local Anvil testnet node.

    Args:
        fork_url: RPC URL to fork from
        fork_block: Block number to fork from
        port: Port to listen on (default: 8545)
        accounts: Number of accounts to generate (default: 10)
        balance: Initial balance in ETH for each account (default: 10000)
        args: Additional Anvil arguments

    Returns:
        str: Anvil startup information including accounts and private keys

    Note: This starts Anvil in the background. Use anvil_stop to terminate.
    """
    cmd_parts = [ANVIL_PATH]

    if fork_url:
        cmd_parts.append(f"--fork-url {fork_url}")

    if fork_block:
        cmd_parts.append(f"--fork-block-number {fork_block}")

    cmd_parts.append(f"--port {port}")
    cmd_parts.append(f"--accounts {accounts}")
    cmd_parts.append(f"--balance {balance}")

    if args:
        cmd_parts.append(args)

    # Run in background and capture initial output
    cmd_parts.append("&")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf, timeout=10)
