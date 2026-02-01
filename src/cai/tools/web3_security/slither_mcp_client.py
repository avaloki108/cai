"""
Slither MCP Client Integration for Aegis

This module provides @function_tool wrappers around the SlitherMCPClient,
enabling typed access to Slither's static analysis capabilities through the
slither-mcp MCP server.

Features:
- Singleton pattern for efficient client lifecycle management
- Automatic project path resolution from CTF context or AEGIS_WORKSPACE
- Full type safety using slither-mcp's Pydantic models
- Caching via slither-mcp's built-in ProjectFacts caching

Usage:
    from cai.tools.web3_security.slither_mcp_client import (
        slither_mcp_list_contracts,
        slither_mcp_run_detectors,
    )
"""

from __future__ import annotations

import asyncio
import os
import warnings
from typing import Any, Optional, List, Dict

from cai.sdk.agents import function_tool

# Lazy imports to avoid requiring slither-mcp as a hard dependency
_CLIENT: Optional[Any] = None
_CLIENT_LOCK = asyncio.Lock()


def _get_project_path(explicit_path: Optional[str] = None, ctf: Any = None) -> str:
    """
    Resolve project path with fallback chain:
    1. Explicit path parameter
    2. CTF.project_path if in CTF context
    3. AEGIS_WORKSPACE environment variable
    4. Current working directory
    """
    if explicit_path:
        return os.path.abspath(explicit_path)
    
    if ctf and hasattr(ctf, 'project_path') and ctf.project_path:
        return os.path.abspath(ctf.project_path)
    
    workspace = os.getenv("AEGIS_WORKSPACE")
    if workspace:
        return os.path.abspath(workspace)
    
    return os.getcwd()


async def _get_client(project_path: str) -> Any:
    """
    Get or create the SlitherMCPClient singleton.
    
    Uses a singleton pattern to avoid spawning multiple MCP server processes.
    If the project path changes, a new client is created.
    """
    global _CLIENT
    
    async with _CLIENT_LOCK:
        # Import lazily to avoid hard dependency
        try:
            from slither_mcp.client import SlitherMCPClient
        except ImportError:
            raise ImportError(
                "slither-mcp is not installed. Install it with: "
                "pip install slither-mcp or uv pip install slither-mcp"
            )
        
        # Create new client if none exists or project path changed
        if _CLIENT is None or _CLIENT._project_path != os.path.abspath(project_path):
            if _CLIENT is not None:
                await _CLIENT.close()
            
            _CLIENT = SlitherMCPClient(project_path)
            await _CLIENT.connect()
        
        return _CLIENT


async def _close_client():
    """Close the SlitherMCPClient if it exists."""
    global _CLIENT
    
    async with _CLIENT_LOCK:
        if _CLIENT is not None:
            await _CLIENT.close()
            _CLIENT = None


# =============================================================================
# Query Tools
# =============================================================================

@function_tool
async def slither_mcp_list_contracts(
    path: Optional[str] = None,
    filter_type: str = "all",
    path_pattern: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    List all contracts in a Solidity project with optional filters.
    
    Uses Slither's static analysis to extract contract metadata including
    name, type (concrete/abstract/interface/library), and file path.
    
    Args:
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
        filter_type: Filter by contract type. Options: "all", "concrete", 
                     "abstract", "interface", "library". Default: "all"
        path_pattern: Filter by path substring (e.g., "src/" to exclude test/).
    
    Returns:
        JSON string with list of contracts including name, path, and type info.
    
    Example:
        # List only concrete (non-abstract, non-interface) contracts
        slither_mcp_list_contracts(filter_type="concrete")
        
        # List contracts in src/ directory only
        slither_mcp_list_contracts(path_pattern="src/")
    """
    try:
        from slither_mcp.tools import ListContractsRequest
    except ImportError:
        return "ERROR: slither-mcp is not installed. Install with: pip install slither-mcp"
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        request = ListContractsRequest(
            path=project_path,
            filter_type=filter_type,
            path_pattern=path_pattern,
        )
        response = await client.list_contracts(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        # Format contracts for display
        contracts = []
        for c in response.contracts:
            contracts.append({
                "name": c.key.contract_name,
                "path": c.key.path,
                "is_abstract": c.is_abstract,
                "is_interface": c.is_interface,
                "is_library": c.is_library,
                "function_count": c.function_count,
            })
        
        import json
        return json.dumps({"contracts": contracts, "total": len(contracts)}, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_get_contract(
    contract_name: str,
    contract_path: str,
    include_functions: bool = True,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get detailed information about a specific contract.
    
    Retrieves comprehensive metadata including functions (declared and inherited),
    inheritance hierarchy, state variables, events, and modifiers.
    
    Args:
        contract_name: Name of the contract (e.g., "MyToken")
        contract_path: Relative path to the contract file (e.g., "src/MyToken.sol")
        include_functions: Whether to include function details. Default: True
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON string with detailed contract information.
    
    Example:
        slither_mcp_get_contract("MyToken", "src/MyToken.sol")
    """
    try:
        from slither_mcp.tools import GetContractRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        request = GetContractRequest(
            path=project_path,
            contract_key=contract_key,
            include_functions=include_functions,
        )
        response = await client.get_contract(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        contract = response.contract
        result = {
            "name": contract.name,
            "path": contract.path,
            "is_abstract": contract.is_abstract,
            "is_interface": contract.is_interface,
            "is_library": contract.is_library,
            "directly_inherits": [
                {"name": k.contract_name, "path": k.path}
                for k in contract.directly_inherits
            ],
            "state_variables": [
                {"name": sv.name, "type": sv.type_str, "visibility": sv.visibility}
                for sv in contract.state_variables
            ],
            "events": [
                {"name": e.name, "parameters": [p.name for p in e.parameters]}
                for e in contract.events
            ],
        }
        
        if include_functions:
            result["functions_declared"] = [
                {
                    "signature": sig,
                    "visibility": f.visibility,
                    "modifiers": f.function_modifiers,
                }
                for sig, f in contract.functions_declared.items()
            ]
            result["functions_inherited"] = list(contract.functions_inherited.keys())
        
        import json
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_list_functions(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    visibility: Optional[List[str]] = None,
    has_modifiers: Optional[List[str]] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    List functions in a Solidity project with optional filters.
    
    Can filter by contract, visibility (public/external/internal/private),
    or by presence of specific modifiers (e.g., onlyOwner).
    
    Args:
        contract_name: Filter to functions in this contract only.
        contract_path: Path to the contract file (required if contract_name set).
        visibility: Filter by visibility. E.g., ["public", "external"]
        has_modifiers: Filter by required modifiers. E.g., ["onlyOwner"]
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON string with list of functions including signature and metadata.
    
    Example:
        # List all public/external functions
        slither_mcp_list_functions(visibility=["public", "external"])
        
        # List functions with onlyOwner modifier
        slither_mcp_list_functions(has_modifiers=["onlyOwner"])
    """
    try:
        from slither_mcp.tools import ListFunctionsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = ListFunctionsRequest(
            path=project_path,
            contract_key=contract_key,
            visibility=visibility,
            has_modifiers=has_modifiers,
        )
        response = await client.list_functions(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        functions = []
        for f in response.functions:
            functions.append({
                "signature": f.key.signature,
                "contract": f.key.contract_name,
                "path": f.key.path,
                "visibility": f.visibility,
                "modifiers": f.modifiers,
            })
        
        import json
        return json.dumps({"functions": functions, "total": len(functions)}, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_get_function_source(
    contract_name: str,
    contract_path: str,
    function_signature: str,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get the source code of a specific function.
    
    Retrieves the complete source code including line numbers, useful for
    detailed code review and vulnerability analysis.
    
    Args:
        contract_name: Name of the contract containing the function.
        contract_path: Relative path to the contract file.
        function_signature: Function signature (e.g., "transfer(address,uint256)")
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        Source code of the function with line numbers.
    
    Example:
        slither_mcp_get_function_source(
            "ERC20", "src/ERC20.sol", "transfer(address,uint256)"
        )
    """
    try:
        from slither_mcp.tools import GetFunctionSourceRequest
        from slither_mcp.types import FunctionKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        function_key = FunctionKey(
            signature=function_signature,
            contract_name=contract_name,
            path=contract_path,
        )
        request = GetFunctionSourceRequest(
            path=project_path,
            function_key=function_key,
        )
        response = await client.get_function_source(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        result = f"// File: {response.file_path}\n"
        result += f"// Lines {response.start_line}-{response.end_line}\n\n"
        result += response.source_code
        
        return result
    
    except Exception as e:
        return f"ERROR: {str(e)}"


# =============================================================================
# Analysis Tools
# =============================================================================

@function_tool
async def slither_mcp_function_callees(
    contract_name: str,
    contract_path: str,
    function_signature: str,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get functions called by a specific function (callees).
    
    Returns internal, external, and library function calls, as well as
    information about low-level calls (call, delegatecall, staticcall).
    Essential for understanding control flow and attack surfaces.
    
    Args:
        contract_name: Name of the contract containing the function.
        contract_path: Relative path to the contract file.
        function_signature: Function signature (e.g., "withdraw(uint256)")
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with internal_callees, external_callees, library_callees,
        and has_low_level_calls flag.
    
    Example:
        # Analyze what functions are called during a withdrawal
        slither_mcp_function_callees(
            "Vault", "src/Vault.sol", "withdraw(uint256)"
        )
    """
    try:
        from slither_mcp.tools import FunctionCalleesRequest
        from slither_mcp.types import FunctionKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        function_key = FunctionKey(
            signature=function_signature,
            contract_name=contract_name,
            path=contract_path,
        )
        request = FunctionCalleesRequest(
            path=project_path,
            function_key=function_key,
        )
        response = await client.function_callees(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        result = {
            "internal_callees": response.callees.internal_callees,
            "external_callees": response.callees.external_callees,
            "library_callees": response.callees.library_callees,
            "has_low_level_calls": response.callees.has_low_level_calls,
        }
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_function_callers(
    contract_name: str,
    contract_path: str,
    function_signature: str,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get all functions that call a specific function (callers).
    
    Returns internal, external, and library callers grouped by type.
    Useful for understanding which code paths lead to a function and
    potential attack entry points.
    
    Args:
        contract_name: Name of the contract containing the function.
        contract_path: Relative path to the contract file.
        function_signature: Function signature (e.g., "_transfer(address,address,uint256)")
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with internal_callers, external_callers, and library_callers.
    
    Example:
        # Find what calls the internal _transfer function
        slither_mcp_function_callers(
            "ERC20", "src/ERC20.sol", "_transfer(address,address,uint256)"
        )
    """
    try:
        from slither_mcp.tools import FunctionCallersRequest
        from slither_mcp.types import FunctionKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        function_key = FunctionKey(
            signature=function_signature,
            contract_name=contract_name,
            path=contract_path,
        )
        request = FunctionCallersRequest(
            path=project_path,
            function_key=function_key,
        )
        response = await client.function_callers(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        result = {
            "internal_callers": response.internal_callers,
            "external_callers": response.external_callers,
            "library_callers": response.library_callers,
        }
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_get_inheritance(
    contract_name: str,
    contract_path: str,
    direction: str = "parents",
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get contract inheritance hierarchy.
    
    Can retrieve either parent contracts (what this contract inherits from)
    or derived contracts (what inherits from this contract).
    
    Args:
        contract_name: Name of the contract.
        contract_path: Relative path to the contract file.
        direction: "parents" for inherited contracts, "children" for derived.
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with recursive inheritance tree.
    
    Example:
        # Get what ERC20 inherits from
        slither_mcp_get_inheritance("MyToken", "src/MyToken.sol", "parents")
        
        # Get what inherits from a base contract
        slither_mcp_get_inheritance("Ownable", "src/Ownable.sol", "children")
    """
    try:
        from slither_mcp.tools import GetInheritedContractsRequest, GetDerivedContractsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        if direction == "parents":
            request = GetInheritedContractsRequest(
                path=project_path,
                contract_key=contract_key,
            )
            response = await client.get_inherited_contracts(request)
        else:
            request = GetDerivedContractsRequest(
                path=project_path,
                contract_key=contract_key,
            )
            response = await client.get_derived_contracts(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        def format_tree(node) -> dict:
            return {
                "name": node.contract_key.contract_name,
                "path": node.contract_key.path,
                "children": [format_tree(c) for c in (node.children if hasattr(node, 'children') else node.parents if hasattr(node, 'parents') else [])],
            }
        
        import json
        tree = format_tree(response.root) if response.root else {}
        return json.dumps({"inheritance_tree": tree, "direction": direction}, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


# =============================================================================
# Security Tools
# =============================================================================

@function_tool
async def slither_mcp_run_detectors(
    detector_names: Optional[List[str]] = None,
    impact: Optional[List[str]] = None,
    confidence: Optional[List[str]] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Run Slither security detectors and get vulnerability findings.
    
    Executes Slither's built-in detectors to identify common vulnerabilities
    like reentrancy, access control issues, and more. Results are cached
    for fast subsequent queries.
    
    Args:
        detector_names: Specific detectors to run. E.g., ["reentrancy-eth", "arbitrary-send-eth"]
                       If None, runs all detectors.
        impact: Filter by impact level. Options: ["High", "Medium", "Low", "Informational"]
        confidence: Filter by confidence. Options: ["High", "Medium", "Low"]
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with detector findings including description, impact, confidence,
        and source locations.
    
    Example:
        # Run high-impact detectors only
        slither_mcp_run_detectors(impact=["High"])
        
        # Run specific reentrancy detectors
        slither_mcp_run_detectors(detector_names=["reentrancy-eth", "reentrancy-no-eth"])
    """
    try:
        from slither_mcp.tools import RunDetectorsRequest
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        request = RunDetectorsRequest(
            path=project_path,
            detector_names=detector_names,
            impact=impact,
            confidence=confidence,
        )
        response = await client.run_detectors(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        findings = []
        for result in response.results:
            findings.append({
                "detector": result.detector_name,
                "check": result.check,
                "impact": result.impact,
                "confidence": result.confidence,
                "description": result.description,
                "locations": [
                    {
                        "file": loc.file_path,
                        "start_line": loc.start_line,
                        "end_line": loc.end_line,
                    }
                    for loc in result.source_locations
                ],
            })
        
        import json
        return json.dumps({
            "findings": findings,
            "total": len(findings),
            "filters": {
                "detector_names": detector_names,
                "impact": impact,
                "confidence": confidence,
            }
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_list_detectors(
    name_filter: Optional[str] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    List available Slither security detectors.
    
    Returns metadata about each detector including name, description,
    impact level, and confidence rating. Use this to understand what
    security checks are available.
    
    Args:
        name_filter: Filter detectors by name substring.
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with detector metadata including name, description, impact, confidence.
    
    Example:
        # List all reentrancy-related detectors
        slither_mcp_list_detectors(name_filter="reentrancy")
    """
    try:
        from slither_mcp.tools import ListDetectorsRequest
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        request = ListDetectorsRequest(
            path=project_path,
            name_filter=name_filter,
        )
        response = await client.list_detectors(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        detectors = []
        for d in response.detectors:
            detectors.append({
                "name": d.name,
                "description": d.description,
                "impact": d.impact,
                "confidence": d.confidence,
            })
        
        import json
        return json.dumps({"detectors": detectors, "total": len(detectors)}, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_get_contract_source(
    contract_name: str,
    contract_path: str,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get the complete source code of a contract file.
    
    Retrieves the full source code of the Solidity file containing the
    specified contract. Useful for comprehensive code review.
    
    Args:
        contract_name: Name of the contract.
        contract_path: Relative path to the contract file.
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        Complete source code of the contract file.
    
    Example:
        slither_mcp_get_contract_source("MyToken", "src/MyToken.sol")
    """
    try:
        from slither_mcp.tools import GetContractSourceRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        request = GetContractSourceRequest(
            path=project_path,
            contract_key=contract_key,
        )
        response = await client.get_contract_source(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        return f"// File: {response.file_path}\n\n{response.source_code}"
    
    except Exception as e:
        return f"ERROR: {str(e)}"


# =============================================================================
# Helper Functions
# =============================================================================

@function_tool
async def slither_mcp_get_project_overview(
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Get a high-level overview of a Solidity project.
    
    Returns summary statistics including total contracts, functions,
    inheritance relationships, and key metrics useful for initial
    project understanding.
    
    Args:
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with project overview including contract counts, function counts,
        and key statistics.
    
    Example:
        slither_mcp_get_project_overview()
    """
    try:
        from slither_mcp.tools import ListContractsRequest, ListFunctionsRequest
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        # Get contract statistics
        contracts_request = ListContractsRequest(path=project_path, filter_type="all")
        contracts_response = await client.list_contracts(contracts_request)
        
        if not contracts_response.success:
            return f"ERROR: {contracts_response.error_message}"
        
        contracts = contracts_response.contracts
        
        # Count by type
        concrete = sum(1 for c in contracts if not c.is_abstract and not c.is_interface and not c.is_library)
        abstract = sum(1 for c in contracts if c.is_abstract)
        interfaces = sum(1 for c in contracts if c.is_interface)
        libraries = sum(1 for c in contracts if c.is_library)
        
        # Get total function count
        total_functions = sum(c.function_count for c in contracts)
        
        import json
        return json.dumps({
            "project_path": project_path,
            "contracts": {
                "total": len(contracts),
                "concrete": concrete,
                "abstract": abstract,
                "interfaces": interfaces,
                "libraries": libraries,
            },
            "functions": {
                "total": total_functions,
            },
            "files": list(set(c.key.path for c in contracts)),
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


# =============================================================================
# Custom Security Analyzers (from slither-mcp custom tools)
# =============================================================================

@function_tool
async def slither_mcp_analyze_reentrancy(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    min_severity: str = "Medium",
    include_read_only: bool = False,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Detect reentrancy patterns beyond standard Slither detectors.
    
    Identifies classic, cross-function, cross-contract, and read-only 
    reentrancy patterns using advanced call graph analysis.
    
    Args:
        contract_name: Analyze specific contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        min_severity: Minimum severity to report. Options: "High", "Medium", "Low"
        include_read_only: Include read-only reentrancy patterns (lower severity).
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with reentrancy patterns found, including type, severity, and 
        affected functions.
    
    Example:
        # Analyze all contracts for medium+ severity reentrancy
        slither_mcp_analyze_reentrancy(min_severity="Medium")
        
        # Analyze specific contract including read-only patterns
        slither_mcp_analyze_reentrancy(
            contract_name="Vault", 
            contract_path="src/Vault.sol",
            include_read_only=True
        )
    """
    try:
        from slither_mcp.tools import AnalyzeReentrancyPatternsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeReentrancyPatternsRequest(
            path=project_path,
            contract_key=contract_key,
            min_severity=min_severity,
            include_read_only=include_read_only,
        )
        response = await client.analyze_reentrancy_patterns(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        patterns = []
        for p in response.patterns:
            patterns.append({
                "type": p.pattern_type,
                "severity": p.severity,
                "function": p.function_key.signature if p.function_key else None,
                "contract": p.function_key.contract_name if p.function_key else None,
                "description": p.description,
                "external_calls": p.external_calls,
                "state_changes_after": p.state_changes_after,
            })
        
        return json.dumps({
            "patterns": patterns,
            "total": response.total_count,
            "summary": response.summary,
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_access_control(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    include_informational: bool = False,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Analyze access control patterns and identify issues.
    
    Detects missing access controls, centralization risks, and maps
    modifier usage across contracts.
    
    Args:
        contract_name: Analyze specific contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        include_informational: Include low-severity informational findings.
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with access control issues and modifier mappings.
    
    Example:
        # Analyze all contracts for access control issues
        slither_mcp_analyze_access_control()
        
        # Get detailed analysis of a specific contract
        slither_mcp_analyze_access_control(
            contract_name="Governance",
            contract_path="src/Governance.sol",
            include_informational=True
        )
    """
    try:
        from slither_mcp.tools import AnalyzeAccessControlRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeAccessControlRequest(
            path=project_path,
            contract_key=contract_key,
            include_informational=include_informational,
        )
        response = await client.analyze_access_control(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        issues = []
        for issue in response.issues:
            issues.append({
                "type": issue.issue_type,
                "severity": issue.severity,
                "function": issue.function_key.signature if issue.function_key else None,
                "contract": issue.function_key.contract_name if issue.function_key else None,
                "description": issue.description,
                "recommendation": issue.recommendation,
            })
        
        return json.dumps({
            "issues": issues,
            "total": response.total_count,
            "modifier_mappings": [
                {"modifier": m.modifier_name, "function_count": len(m.functions_using)}
                for m in response.modifier_mappings
            ],
            "summary": response.summary,
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_erc4626(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Analyze ERC4626 vault implementations for common vulnerabilities.
    
    Detects first depositor attacks (inflation attacks), rounding issues,
    missing virtual asset/share offsets, and reentrancy in deposit/withdraw.
    
    Args:
        contract_name: Analyze specific vault contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with ERC4626-specific vulnerabilities and metrics.
    
    Example:
        # Analyze all vaults in the project
        slither_mcp_analyze_erc4626()
        
        # Analyze a specific vault
        slither_mcp_analyze_erc4626(
            contract_name="StakingVault",
            contract_path="src/vaults/StakingVault.sol"
        )
    """
    try:
        from slither_mcp.tools import AnalyzeERC4626VaultRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeERC4626VaultRequest(
            path=project_path,
            contract_key=contract_key,
        )
        response = await client.analyze_erc4626_vault(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        issues = []
        for issue in response.issues:
            issues.append({
                "type": issue.issue_type,
                "severity": issue.severity,
                "contract": issue.contract_key.contract_name if issue.contract_key else None,
                "description": issue.description,
                "recommendation": issue.recommendation,
            })
        
        return json.dumps({
            "issues": issues,
            "total": len(response.issues),
            "vault_count": response.vault_count,
            "metrics": response.metrics.model_dump() if response.metrics else None,
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_amm(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Analyze AMM/DEX patterns for common vulnerabilities.
    
    Detects missing slippage protection, deadline checks, sandwich attack
    vulnerabilities, oracle manipulation risks, and K-invariant issues.
    
    Args:
        contract_name: Analyze specific AMM contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with AMM-specific vulnerabilities and metrics.
    
    Example:
        slither_mcp_analyze_amm()
    """
    try:
        from slither_mcp.tools import AnalyzeAMMPatternsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeAMMPatternsRequest(
            path=project_path,
            contract_key=contract_key,
        )
        response = await client.analyze_amm_patterns(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        issues = []
        for issue in response.issues:
            issues.append({
                "type": issue.issue_type,
                "severity": issue.severity,
                "contract": issue.contract_key.contract_name if issue.contract_key else None,
                "description": issue.description,
                "recommendation": issue.recommendation,
            })
        
        return json.dumps({
            "issues": issues,
            "total": len(response.issues),
            "amm_count": response.amm_count,
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_lending(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Analyze lending pool implementations for vulnerabilities.
    
    Detects liquidation issues, oracle manipulation risks, collateral
    factor misconfigurations, flash loan attack vectors, and reentrancy
    in borrow/repay functions.
    
    Args:
        contract_name: Analyze specific lending contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with lending-specific vulnerabilities and metrics.
    
    Example:
        slither_mcp_analyze_lending()
    """
    try:
        from slither_mcp.tools import AnalyzeLendingPoolRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeLendingPoolRequest(
            path=project_path,
            contract_key=contract_key,
        )
        response = await client.analyze_lending_pool(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        issues = []
        for issue in response.issues:
            issues.append({
                "type": issue.issue_type,
                "severity": issue.severity,
                "contract": issue.contract_key.contract_name if issue.contract_key else None,
                "description": issue.description,
                "recommendation": issue.recommendation,
            })
        
        return json.dumps({
            "issues": issues,
            "total": len(response.issues),
            "lending_pool_count": response.lending_pool_count,
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_cross_contract(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    include_trusted: bool = False,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Analyze cross-contract interactions for security issues.
    
    Maps trust boundaries, identifies callback vulnerabilities, untrusted
    external calls, and delegatecall risks.
    
    Args:
        contract_name: Analyze specific contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        include_trusted: Include trusted external calls in analysis.
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with cross-contract issues and trust boundary map.
    
    Example:
        slither_mcp_analyze_cross_contract()
    """
    try:
        from slither_mcp.tools import AnalyzeCrossContractCallsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeCrossContractCallsRequest(
            path=project_path,
            contract_key=contract_key,
            include_trusted=include_trusted,
        )
        response = await client.analyze_cross_contract_calls(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        issues = []
        for issue in response.issues:
            issues.append({
                "type": issue.issue_type,
                "severity": issue.severity,
                "function": issue.function_key.signature if issue.function_key else None,
                "contract": issue.function_key.contract_name if issue.function_key else None,
                "description": issue.description,
            })
        
        return json.dumps({
            "issues": issues,
            "total": len(response.issues),
            "call_count": len(response.calls),
            "trust_boundaries": len(response.trust_boundaries),
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_analyze_invariants(
    contract_name: Optional[str] = None,
    contract_path: Optional[str] = None,
    generate_fuzzing_config: Optional[str] = None,
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Extract protocol invariants and optionally generate fuzzing configs.
    
    Infers balance, supply, ownership, access control, and mathematical
    invariants from contract code. Can generate Echidna or Medusa configs.
    
    Args:
        contract_name: Analyze specific contract (optional).
        contract_path: Path to contract file (required if contract_name set).
        generate_fuzzing_config: Generate config for "echidna" or "medusa".
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with extracted invariants and optional fuzzing configuration.
    
    Example:
        # Extract invariants
        slither_mcp_analyze_invariants()
        
        # Extract invariants and generate Echidna config
        slither_mcp_analyze_invariants(generate_fuzzing_config="echidna")
    """
    try:
        from slither_mcp.tools import AnalyzeInvariantsRequest
        from slither_mcp.types import ContractKey
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        contract_key = None
        if contract_name and contract_path:
            contract_key = ContractKey(contract_name=contract_name, path=contract_path)
        
        request = AnalyzeInvariantsRequest(
            path=project_path,
            contract_key=contract_key,
            generate_fuzzing_config=generate_fuzzing_config,
        )
        response = await client.analyze_invariants(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        invariants = []
        for inv in response.invariants:
            invariants.append({
                "type": inv.invariant_type,
                "expression": inv.expression,
                "description": inv.description,
                "contract": inv.contract_key.contract_name if inv.contract_key else None,
                "confidence": inv.confidence,
            })
        
        result = {
            "invariants": invariants,
            "total": len(response.invariants),
            "violation_risks": [
                {"invariant": r.invariant.expression, "risk": r.risk_level, "reason": r.violation_reason}
                for r in response.violation_risks
            ],
        }
        
        if response.fuzzing_config:
            result["fuzzing_config"] = {
                "tool": response.fuzzing_config.tool,
                "config": response.fuzzing_config.config_content,
            }
        
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


@function_tool
async def slither_mcp_run_custom_detectors(
    detector_names: Optional[List[str]] = None,
    category: Optional[str] = None,
    min_severity: str = "Low",
    path: Optional[str] = None,
    ctf: Any = None
) -> str:
    """
    Run custom security detectors beyond standard Slither.
    
    Includes specialized checks for DeFi patterns, economic attacks,
    and protocol-specific vulnerabilities.
    
    Args:
        detector_names: Specific custom detectors to run (optional).
        category: Filter by category: "defi", "economic", "access_control", etc.
        min_severity: Minimum severity. Options: "Critical", "High", "Medium", "Low"
        path: Path to Solidity project. Defaults to AEGIS_WORKSPACE or CWD.
    
    Returns:
        JSON with custom detector findings.
    
    Example:
        # Run all custom detectors
        slither_mcp_run_custom_detectors()
        
        # Run only DeFi-specific detectors
        slither_mcp_run_custom_detectors(category="defi")
    """
    try:
        from slither_mcp.tools import RunCustomDetectorsRequest
    except ImportError:
        return "ERROR: slither-mcp is not installed."
    
    project_path = _get_project_path(path, ctf)
    
    try:
        client = await _get_client(project_path)
        
        request = RunCustomDetectorsRequest(
            path=project_path,
            detector_names=detector_names,
            category=category,
            min_severity=min_severity,
        )
        response = await client.run_custom_detectors(request)
        
        if not response.success:
            return f"ERROR: {response.error_message}"
        
        import json
        findings = []
        for f in response.findings:
            findings.append({
                "detector": f.detector_name,
                "severity": f.severity,
                "category": f.category,
                "contract": f.contract_key.contract_name if f.contract_key else None,
                "function": f.function_key.signature if f.function_key else None,
                "description": f.description,
                "recommendation": f.recommendation,
            })
        
        return json.dumps({
            "findings": findings,
            "total": len(response.findings),
            "detectors_run": [d.name for d in response.detectors_run],
        }, indent=2)
    
    except Exception as e:
        return f"ERROR: {str(e)}"


# Export all tools
__all__ = [
    # Query Tools
    "slither_mcp_list_contracts",
    "slither_mcp_get_contract",
    "slither_mcp_list_functions",
    "slither_mcp_get_function_source",
    "slither_mcp_get_contract_source",
    # Analysis Tools
    "slither_mcp_function_callees",
    "slither_mcp_function_callers",
    "slither_mcp_get_inheritance",
    # Security Tools
    "slither_mcp_run_detectors",
    "slither_mcp_list_detectors",
    # Custom Security Analyzers
    "slither_mcp_analyze_reentrancy",
    "slither_mcp_analyze_access_control",
    "slither_mcp_analyze_erc4626",
    "slither_mcp_analyze_amm",
    "slither_mcp_analyze_lending",
    "slither_mcp_analyze_cross_contract",
    "slither_mcp_analyze_invariants",
    "slither_mcp_run_custom_detectors",
    # Helper Functions
    "slither_mcp_get_project_overview",
    # Internal
    "_close_client",
]
