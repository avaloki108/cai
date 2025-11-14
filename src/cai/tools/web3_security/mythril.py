"""
Mythril security analysis tool for EVM bytecode.
Mythril uses symbolic execution, SMT solving, and taint analysis to detect
security vulnerabilities in Ethereum smart contracts.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import MYTHRIL_PATH


@function_tool
def mythril_analyze(target: str, args: str = "", ctf=None) -> str:
    """
    Run Mythril security analysis on Ethereum smart contracts or bytecode.

    Mythril performs symbolic execution and SMT solving to detect vulnerabilities
    like integer overflows, reentrancy, unprotected functions, etc.

    Args:
        target: Path to Solidity file, bytecode file, or contract address
        args: Additional Mythril arguments
              Common options:
              - --solv <version>: Specify Solidity compiler version
              - -a <address>: Analyze contract at address (requires --rpc)
              - --rpc <url>: RPC endpoint for on-chain analysis
              - -o <format>: Output format (text, json, markdown, jsonv2)
              - --max-depth <n>: Maximum recursion depth (default: 128)
              - --execution-timeout <sec>: Execution timeout in seconds
              - --create-timeout <sec>: Creation timeout in seconds
              - --solver-timeout <ms>: SMT solver timeout in milliseconds
              - --strategy <strategy>: Analysis strategy (dfs, bfs)

    Returns:
        str: Mythril analysis output with detected vulnerabilities

    Examples:
        - Analyze Solidity file: mythril_analyze("contract.sol")
        - Analyze on-chain contract: mythril_analyze("0x...", "-a 0x... --rpc https://eth-mainnet.alchemyapi.io/...")
        - JSON output: mythril_analyze("contract.sol", "-o json")
        - Set timeout: mythril_analyze("contract.sol", "--execution-timeout 300")
    """
    command = f'{MYTHRIL_PATH} analyze {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def mythril_disassemble(target: str, args: str = "", ctf=None) -> str:
    """
    Disassemble EVM bytecode using Mythril.

    Args:
        target: Path to bytecode file or contract address
        args: Additional arguments for disassembly

    Returns:
        str: Disassembled EVM bytecode
    """
    command = f'{MYTHRIL_PATH} disassemble {args} {target}'
    return run_command(command, ctf=ctf)


@function_tool
def mythril_read_storage(address: str, position: str, rpc_url: str, args: str = "", ctf=None) -> str:
    """
    Read storage from a contract using Mythril.

    Args:
        address: Contract address
        position: Storage position to read
        rpc_url: RPC endpoint URL
        args: Additional arguments

    Returns:
        str: Storage value at specified position
    """
    command = f'{MYTHRIL_PATH} read-storage {address} {position} --rpc {rpc_url} {args}'
    return run_command(command, ctf=ctf)
