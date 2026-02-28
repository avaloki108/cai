import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from cai.sdk.agents import function_tool

def _read_file(p: Path) -> str:
    """Read file content safely."""
    try:
        # Only read up to 100KB to avoid memory issues and ignore large binaries
        with open(p, "rb") as f:
            data = f.read(100_000)
            return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _identify_proxy_type(content: str, filename: str) -> Optional[str]:
    """Identify the type of proxy pattern in a contract file."""
    # Diamond (EIP-2535) - Often uses specific facet or storage patterns
    if re.search(r"DiamondCutFacet|IDiamondCut|EIP-2535|DiamondStorage", content):
        return "Diamond"
    # UUPS (EIP-1822)
    if re.search(r"UUPSUpgradeable|_authorizeUpgrade", content):
        return "UUPS"
    # Transparent Proxy (OpenZeppelin standard)
    if re.search(r"TransparentUpgradeableProxy|ProxyAdmin", content):
        return "Transparent"
    # Beacon Proxy (EIP-3448)
    if re.search(r"UpgradeableBeacon|BeaconProxy", content):
        return "Beacon"
    # Minimal Proxy (EIP-1167) - Usually hardcoded bytes
    if "0x363d3d373d3d3d363d73" in content.lower() or "363d3d373d3d3d363d73" in content.lower():
        return "EIP-1167 (Minimal Proxy)"
    # ERC-1967 (Standard Proxy Storage Slots)
    if "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" in content.lower():
        return "ERC-1967 Standard Proxy"
    # General / Custom Proxy detection
    # Look for delegatecall in files that look like proxies
    if re.search(r"delegatecall\s*\(", content):
        if any(x in filename or x in content for x in ["Proxy", "Delegate", "Implementation"]):
            return "Custom Proxy (delegatecall)"
    
    return None

def _check_initialization_state(repo_path: str, ctf=None) -> str:
    """
    Analyzes smart contract initialization logic and cross-references 
    with deployment artifacts (Foundry/Hardhat) to identify gaps.
    
    This tool performs Temporal State Analysis by checking:
    1. Implementation Protection: Does the constructor call _disableInitializers()?
    2. Logic Gaps: Are initialize functions properly guarded by modifiers?
    3. Deployment Gaps: Are proxies deployed without a recorded initialize call?
    
    Args:
        repo_path: Path to the repository root to scan.
        
    Returns:
        JSON string with initialization risks and deployment verification.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)
    
    implementations = []
    deployment_artifacts = []
    
    # Helper for reading text files
    def read_text(p: Path) -> str:
        try:
            return p.read_text(errors="ignore")
        except Exception:
            return ""

    # 1. Scan for implementation contracts
    files_scanned = 0
    for p in repo.rglob("*.sol"):
        files_scanned += 1
        if files_scanned > 1000: break
            
        content = _read_file(p)
        if not content: continue
        
        # Heuristics for implementation contracts
        is_impl = any(x in content for x in ["Initializable", "initialize(", "reinitializer(", "UUPSUpgradeable"])
        if is_impl:
            # Find the contract name(s) in the file
            contract_names = re.findall(r"contract\s+(\w+)", content)
            
            # Check for _disableInitializers in constructor
            # Heuristic: looks for the keyword in the file
            has_constructor = bool(re.search(r"\bconstructor\s*\(", content))
            has_disable_initializers = "_disableInitializers()" in content
            
            # Check initialize functions and their modifiers
            # Find function initialize(...) ... {
            init_functions = re.findall(r"function\s+initialize\s*\([^)]*\)\s*([^\{]*)", content)
            init_vulnerabilities = []
            for modifiers in init_functions:
                if not any(x in modifiers for x in ["initializer", "reinitializer"]):
                    init_vulnerabilities.append("initialize() missing initializer/reinitializer modifier")
            
            # Check for reinitializer usage (good practice for upgrades)
            uses_reinitializer = "reinitializer(" in content
            
            implementations.append({
                "file": str(p.relative_to(repo)),
                "contracts": contract_names,
                "risks": {
                    "missing_constructor_protection": has_constructor and not has_disable_initializers,
                    "missing_modifiers": init_vulnerabilities,
                    "vulnerable_implementation": not has_disable_initializers # Potential for implementation hijacking
                },
                "best_practices": {
                    "uses_reinitializer": uses_reinitializer
                }
            })
            
    # 2. Scan for deployment artifacts (Foundry broadcast is common)
    broadcast_dir = repo / "broadcast"
    if broadcast_dir.exists():
        for p in broadcast_dir.rglob("*.json"):
            if "dry-run" in str(p): continue
            try:
                data = json.loads(read_text(p))
                transactions = data.get("transactions", [])
                for tx in transactions:
                    # Look for initialize calls (selector 0x8129fc1c)
                    input_data = tx.get("input", "")
                    if input_data.startswith("0x8129fc1c"):
                        deployment_artifacts.append({
                            "type": "initialization_call",
                            "to": tx.get("to"),
                            "contract": tx.get("contractName"),
                            "file": str(p.relative_to(repo))
                        })
                    # Look for proxy deployments
                    if tx.get("type") == "CREATE" and any(x in str(tx.get("contractName", "")) for x in ["Proxy", "UUPS"]):
                         deployment_artifacts.append({
                            "type": "proxy_deployment",
                            "address": tx.get("contractAddress"),
                            "contract": tx.get("contractName"),
                            "file": str(p.relative_to(repo))
                        })
            except Exception:
                continue

    # Cross-verify: Were all proxies initialized?
    uninitialized_proxies = []
    if deployment_artifacts:
        proxies = [d for d in deployment_artifacts if d["type"] == "proxy_deployment"]
        initializations = [d for d in deployment_artifacts if d["type"] == "initialization_call"]
        init_targets = {i["to"].lower() for i in initializations if i.get("to")}
        
        for proxy in proxies:
            addr = proxy.get("address")
            if addr and addr.lower() not in init_targets:
                uninitialized_proxies.append(proxy)

    return json.dumps({
        "implementations": implementations,
        "deployment_artifacts_found": len(deployment_artifacts),
        "uninitialized_proxies_detected": uninitialized_proxies,
        "risks_summary": {
            "impl_vulnerable_to_hijack": len([i for i in implementations if i["risks"]["vulnerable_implementation"]]),
            "missing_modifiers_count": sum(len(i["risks"]["missing_modifiers"]) for i in implementations),
            "uninitialized_deployment_count": len(uninitialized_proxies)
        },
        "recommendation": "Address all vulnerable implementation contracts with _disableInitializers() and ensure all proxies are initialized."
    }, indent=2)

def _discover_proxy_patterns(repo_path: str, ctf=None) -> str:
    """
    Detailed discovery of smart contract proxy patterns in a repository.
    
    Scans Solidity files for UUPS, Transparent, Beacon, Diamond, and other 
    proxy implementations. This tool provides the foundation for initialization 
    gap analysis and upgradeability risk assessment.
    
    Args:
        repo_path: Path to the repository root to scan.
        
    Returns:
        JSON string with identified proxy instances, their types, 
        and initialization state hints.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)
    
    proxies = []
    
    # Scan all .sol files (limit to avoid extreme cases)
    files_scanned = 0
    for p in repo.rglob("*.sol"):
        files_scanned += 1
        if files_scanned > 1000: # Safety limit
            break
            
        content = _read_file(p)
        if not content:
            continue
            
        proxy_type = _identify_proxy_type(content, p.name)
        if proxy_type:
            # Try to find contract name(s) in the file
            contract_names = re.findall(r"contract\s+(\w+)", content)
            
            # Check for initialization patterns
            has_initializer = bool(re.search(r"\binitialize\(|\binitializer\b|\breinitializer\b", content))
            has_constructor = bool(re.search(r"\bconstructor\s*\(", content))
            
            proxies.append({
                "file": str(p.relative_to(repo)),
                "type": proxy_type,
                "contracts": contract_names,
                "features": {
                    "has_initializer": has_initializer,
                    "has_constructor": has_constructor,
                    "uses_delegatecall": bool(re.search(r"delegatecall\s*\(", content))
                }
            })
            
    # Summary of findings
    type_counts = {}
    for p in proxies:
        t = p["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
        
    return json.dumps({
        "repo_path": str(repo),
        "total_proxies": len(proxies),
        "type_breakdown": type_counts,
        "proxies": proxies,
        "recommendation": "Analyze initialization state for all identified proxies (Milestone 2.2)."
    }, indent=2)

@function_tool
def discover_proxy_patterns(repo_path: str, ctf=None) -> str:
    return _discover_proxy_patterns(repo_path, ctf)

@function_tool
def check_initialization_state(repo_path: str, ctf=None) -> str:
    return _check_initialization_state(repo_path, ctf)
