"""
Slither static analysis tool for Solidity smart contracts.
Slither is a Solidity static analysis framework that detects vulnerabilities
and provides detailed information about contract structure.
"""

import os
from typing import Optional
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SLITHER_PATH


@function_tool
def slither_analyze(
    target: str,
    args: str = "",
    solc_version: Optional[str] = None,
    detectors: Optional[str] = None,
    exclude: Optional[str] = None,
    printer: Optional[str] = None,
    json_output: Optional[str] = None,
    ctf=None
) -> str:
    """
    Run Slither static analysis on Solidity smart contracts.

    Slither detects vulnerabilities and code quality issues in Solidity contracts.
    It can analyze single files, directories, or entire projects.

    Args:
        target: Path to Solidity file, directory, or project root to analyze.
                This is REQUIRED - must be a valid file or directory path.
        args: Additional Slither arguments as a string
        solc_version: Solidity compiler version to use (e.g., "0.8.22")
                     Use this when the contract pragma doesn't match your system solc.
        detectors: Comma-separated list of detectors to run (e.g., "reentrancy-eth,arbitrary-send-eth")
        exclude: Comma-separated list of detectors to exclude
        printer: Printer to use (e.g., "human-summary", "contract-summary", "call-graph")
        json_output: Path to export results as JSON

    Returns:
        str: Slither analysis output including detected vulnerabilities and recommendations

    Common Detectors:
        High: arbitrary-send-eth, controlled-delegatecall, reentrancy-eth, suicidal
        Medium: reentrancy-no-eth, locked-ether, unchecked-transfer
        Low: naming-convention, dead-code, unused-state

    Examples:
        - Basic analysis: slither_analyze("/path/to/contract.sol")
        - With solc version: slither_analyze("/path/to/contract.sol", solc_version="0.8.22")
        - Specific detectors: slither_analyze("/path/to/contract.sol", detectors="reentrancy-eth")
        - Human summary: slither_analyze("/path/to/project", printer="human-summary")
    """
    # Validate target
    if not target or not target.strip():
        return "ERROR: target parameter is required. Please provide a path to a Solidity file or project directory."

    # Check if target exists (but allow addresses starting with 0x)
    if not target.startswith("0x") and not os.path.exists(target):
        return f"ERROR: Target path does not exist: {target}"

    # Build command - target comes FIRST, then options
    cmd_parts = [SLITHER_PATH, target]

    # Handle string "null" from JSON parsing - convert to None for all optional parameters
    if isinstance(solc_version, str) and (solc_version.lower() == "null" or solc_version.strip() == ""):
        solc_version = None
    if isinstance(detectors, str):
        if detectors.lower() == "null" or detectors.strip() == "":
            detectors = None
        else:
            # Filter out "null" from comma-separated lists (e.g., "reentrancy-eth,null" -> "reentrancy-eth")
            detector_list = [d.strip() for d in detectors.split(",")]
            filtered_list = [d for d in detector_list if d.lower() != "null" and d.strip() != ""]
            if filtered_list:
                detectors = ",".join(filtered_list)
            else:
                detectors = None
    if isinstance(exclude, str):
        if exclude.lower() == "null" or exclude.strip() == "":
            exclude = None
        else:
            # Filter out "null" from comma-separated lists
            exclude_list = [e.strip() for e in exclude.split(",")]
            filtered_list = [e for e in exclude_list if e.lower() != "null" and e.strip() != ""]
            if filtered_list:
                exclude = ",".join(filtered_list)
            else:
                exclude = None
    if isinstance(printer, str) and (printer.lower() == "null" or printer.strip() == ""):
        printer = None
    if isinstance(json_output, str) and (json_output.lower() == "null" or json_output.strip() == ""):
        json_output = None

    # Add solc version if specified
    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    # Add detectors (validate and suggest corrections for common mistakes)
    if detectors:
        # Common invalid detector names and their corrections
        detector_corrections = {
            "arbitrary-storage": "arbitrary-send-eth",  # Mythril detector name confusion
            "unprotected-calls": "unprotected-upgrade",  # Common mistake
            "unchecked-calls": "unchecked-transfer",  # Common mistake
        }
        
        # Check for invalid detector names and provide helpful error
        detector_list = [d.strip() for d in detectors.split(",")]
        invalid_detectors = []
        corrected_detectors = []
        
        for det in detector_list:
            if det in detector_corrections:
                invalid_detectors.append(det)
                corrected_detectors.append(detector_corrections[det])
        
        if invalid_detectors:
            suggestions = ", ".join([f"'{old}' -> '{new}'" for old, new in zip(invalid_detectors, corrected_detectors)])
            return f"ERROR: Invalid Slither detector names detected:\n{suggestions}\n\nUse 'slither_detectors_list' to see all valid detector names."
        
        cmd_parts.append(f"--detect {detectors}")

    # Add exclusions
    if exclude:
        cmd_parts.append(f"--exclude {exclude}")

    # Add printer (validate common invalid names)
    if printer:
        # Common mistakes: "human-summary" should be "contract-summary" or removed
        if printer == "human-summary":
            return "ERROR: 'human-summary' is not a valid Slither printer. Use 'contract-summary' instead, or omit the printer parameter for default output."
        cmd_parts.append(f"--print {printer}")

    # Add JSON output
    if json_output:
        cmd_parts.append(f"--json {json_output}")

    # Add any additional args
    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slither_check_upgradeability(
    target: str,
    proxy_address: str = "",
    solc_version: Optional[str] = None,
    args: str = "",
    ctf=None
) -> str:
    """
    Check upgradeability issues in proxy contracts using Slither.

    Args:
        target: Path to the implementation contract
        proxy_address: Address of the proxy contract (optional)
        solc_version: Solidity compiler version to use
        args: Additional arguments for upgradeability checks

    Returns:
        str: Analysis of upgradeability issues and risks
    """
    if not target or not target.strip():
        return "ERROR: target parameter is required."

    # Handle string "null" from JSON parsing
    if isinstance(solc_version, str) and (solc_version.lower() == "null" or solc_version.strip() == ""):
        solc_version = None
    
    if isinstance(proxy_address, str) and (proxy_address.lower() == "null" or proxy_address.strip() == ""):
        proxy_address = None

    cmd_parts = [SLITHER_PATH, target, "--detect-upgradeability"]

    if proxy_address:
        cmd_parts.append(f"--proxy {proxy_address}")

    if solc_version:
        cmd_parts.append(f"--solc-solcs-select {solc_version}")

    if args:
        cmd_parts.append(args)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def slither_detectors_list(ctf=None) -> str:
    """
    List all available Slither detectors.

    Returns:
        str: List of detectors with descriptions and impact levels
    """
    command = f"{SLITHER_PATH} --list-detectors"
    return run_command(command, ctf=ctf)


@function_tool
def slither_printers_list(ctf=None) -> str:
    """
    List all available Slither printers.

    Returns:
        str: List of printers with descriptions
    """
    command = f"{SLITHER_PATH} --list-printers"
    return run_command(command, ctf=ctf)
