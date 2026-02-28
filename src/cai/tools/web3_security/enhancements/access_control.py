import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from cai.sdk.agents import function_tool

def _read_file(p: Path) -> str:
    """Read file content safely."""
    try:
        # Only read up to 200KB to avoid memory issues and ignore large binaries
        with open(p, "rb") as f:
            data = f.read(200_000)
            return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _extract_roles_and_hierarchy(content: str) -> Dict[str, Any]:
    """Extract role definitions and hierarchy from a Solidity file's content."""
    # Find role constants: bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    # Capture the variable name and the keccak256 value (if possible)
    role_defs = {}
    
    # 1. Capture constants
    # Pattern: bytes32 [visibility] constant NAME = [value];
    # We want to capture the name and the value (even if it's just 0x0 or keccak256(...))
    constant_matches = re.finditer(r"bytes32\s+(?:public|private|internal)?\s*constant\s+(\w+)\s*=\s*([^;]+);", content)
    for m in constant_matches:
        name = m.group(1)
        val = m.group(2).strip()
        role_defs[name] = val
    
    # Also handle some common predefined roles
    if "DEFAULT_ADMIN_ROLE" not in role_defs:
        # Check if DefaultAdminRole is mentioned or if it inherits from AccessControl
        if "AccessControl" in content or "AccessControlUpgradeable" in content:
            role_defs["DEFAULT_ADMIN_ROLE"] = "0x00"

    # 2. Extract hierarchy (_setRoleAdmin)
    # Pattern: _setRoleAdmin(ROLE, ADMIN_ROLE);
    hierarchy = {}
    hierarchy_matches = re.finditer(r"_setRoleAdmin\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)", content)
    for m in hierarchy_matches:
        role = m.group(1)
        admin = m.group(2)
        hierarchy[role] = admin

    # 3. Extract usage (modifiers or checks)
    # onlyRole(ROLE), hasRole(ROLE, ...), _checkRole(ROLE, ...)
    usage_matches = re.findall(r"\bonlyRole\s*\(\s*(\w+)\s*\)", content)
    usage_matches += re.findall(r"hasRole\s*\(\s*(\w+)\s*,", content)
    usage_matches += re.findall(r"_checkRole\s*\(\s*(\w+)\s*,", content)
    
    # 4. Extract Ownership usage
    has_ownable = "Ownable" in content or "OwnableUpgradeable" in content
    uses_only_owner = "onlyOwner" in content
    
    return {
        "role_definitions": role_defs,
        "hierarchy": hierarchy,
        "used_roles": list(set(usage_matches)),
        "is_ownable": has_ownable,
        "uses_only_owner": uses_only_owner
    }

def _construct_role_lattice(repo_path: str, ctf=None) -> str:
    """
    Map the access-control hierarchy (Role Lattice) for a smart contract repository.
    
    This tool performs Authority & Permission Mapping by identifying:
    1. Ownership: Usage of the Ownable pattern.
    2. AccessControl Roles: Mapping bytes32 role constants and their definitions.
    3. Hierarchy: Mapping who is the admin of which role via _setRoleAdmin.
    4. Access Usage: Identifying which roles guard which entrypoints.
    
    Args:
        repo_path: Path to the repository root to scan.
        
    Returns:
        JSON string containing the Role Lattice (Ownership, roles, and hierarchy).
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)
    
    lattice = {
        "global_roles": {}, # role_name -> description/keccak
        "contracts": {}, # contract_name -> { roles, hierarchy, is_ownable }
        "role_hierarchy": {}, # child_role -> parent_role
        "summary": {
            "total_contracts_scanned": 0,
            "ownable_contracts": 0,
            "access_control_contracts": 0,
            "total_roles_found": 0
        }
    }
    
    files_scanned = 0
    contracts_with_access_control = set()
    contracts_with_ownable = set()
    all_roles = set()
    
    # Scan for Solidity files
    for p in repo.rglob("*.sol"):
        # Skip node_modules and lib by default if not explicitly in path
        if "node_modules" in str(p) or "lib" in str(p):
            if repo_path not in str(p): # unless repo_path itself points there
                continue
                
        files_scanned += 1
        if files_scanned > 800: break # Safety limit
            
        content = _read_file(p)
        if not content: continue
        
        # Check if file has any access control keywords
        if not any(x in content for x in ["Ownable", "AccessControl", "onlyRole", "onlyOwner", "hasRole", "bytes32"]):
            continue
            
        # Identify contract name(s) in the file
        contract_names = re.findall(r"contract\s+(\w+)", content)
        if not contract_names: continue
        
        # We'll treat the whole file as the context for these contracts for simplicity
        # (Usually one main contract per file in clean repos)
        file_roles = _extract_roles_and_hierarchy(content)
        
        for name in contract_names:
            lattice["contracts"][name] = {
                "file": str(p.relative_to(repo)),
                "roles": file_roles["role_definitions"],
                "hierarchy": file_roles["hierarchy"],
                "used_roles": file_roles["used_roles"],
                "is_ownable": file_roles["is_ownable"],
                "uses_only_owner": file_roles["uses_only_owner"]
            }
            
            # Update global stats
            if file_roles["is_ownable"] or file_roles["uses_only_owner"]:
                contracts_with_ownable.add(name)
                
            if file_roles["role_definitions"] or file_roles["hierarchy"] or file_roles["used_roles"]:
                contracts_with_access_control.add(name)
                
            for r, val in file_roles["role_definitions"].items():
                all_roles.add(r)
                if r not in lattice["global_roles"]:
                    lattice["global_roles"][r] = val
                    
            for child, parent in file_roles["hierarchy"].items():
                # Store hierarchy
                if child not in lattice["role_hierarchy"]:
                    lattice["role_hierarchy"][child] = []
                if parent not in lattice["role_hierarchy"][child]:
                    lattice["role_hierarchy"][child].append(parent)
                    
    lattice["summary"]["total_contracts_scanned"] = len(lattice["contracts"])
    lattice["summary"]["ownable_contracts"] = len(contracts_with_ownable)
    lattice["summary"]["access_control_contracts"] = len(contracts_with_access_control)
    lattice["summary"]["total_roles_found"] = len(all_roles)
    
    return json.dumps(lattice, indent=2)

construct_role_lattice = function_tool(_construct_role_lattice)


def _detect_privilege_escalation(repo_path: str, ctf=None) -> str:
    """
    Detect privilege escalation paths where low-privilege actors can reach high-privilege sinks.

    Heuristics (minimal, additive, backward-compatible):
    - Unprotected or weakly protected sinks in public/external functions:
      grantRole/_grantRole, revokeRole/_revokeRole, setRoleAdmin/_setRoleAdmin,
      transferOwnership/_transferOwnership/setOwner, upgradeTo/upgradeToAndCall/changeAdmin.
    - Risky role lattice patterns from `construct_role_lattice`:
      self-admin roles (ROLE -> admin ROLE), DEFAULT_ADMIN_ROLE used without separation,
      owner-affecting functions without `onlyOwner`.

    Output:
      JSON with `escalation_paths` array and a `summary`.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)

    # Try to leverage the lattice for context
    lattice_json = construct_role_lattice(repo_path)
    try:
        lattice = json.loads(lattice_json) if isinstance(lattice_json, str) else lattice_json
    except Exception:
        lattice = {"role_hierarchy": {}, "contracts": {}, "global_roles": {}, "summary": {}}

    sinks = [
        "grantRole(", "_grantRole(", "revokeRole(", "_revokeRole(",
        "setRoleAdmin(", "_setRoleAdmin(",
        "transferOwnership(", "_transferOwnership(", "setOwner(",
        "upgradeTo(", "upgradeToAndCall(", "changeAdmin(",
    ]
    guard_markers = [
        "onlyOwner", "onlyRole(", "onlyAdmin", "onlyGovernance",
    ]

    def _find_functions_with_sinks(content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        # Roughly iterate over function definitions
        for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*([^\{;]*)\{", content):
            fname = m.group(1)
            header_tail = m.group(2) or ""
            # Extract body (best-effort) by finding the matching closing brace
            # Simple heuristic: take until next standalone closing brace at column start
            pattern = r"function\\s+" + re.escape(fname) + r"[^\{]*\{([\s\S]*?)\n\s*\}"
            body_match = re.search(pattern, content)
            body = body_match.group(1) if body_match else ""

            # Visibility
            vis = "".join([v for v in [
                "public" if re.search(r"\bpublic\b", header_tail) else "",
                "external" if re.search(r"\bexternal\b", header_tail) else "",
                "internal" if re.search(r"\binternal\b", header_tail) else "",
                "private" if re.search(r"\bprivate\b", header_tail) else "",
            ] if v])

            # Sinks present?
            matched_sinks = [s for s in sinks if s in body or s in header_tail]
            if not matched_sinks:
                continue

            # Guards
            guarded = any(g in header_tail for g in guard_markers)
            if not guarded and body:
                # Look for common guard bodies
                if re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner\s*\)", body, re.IGNORECASE):
                    guarded = True
                if re.search(r"hasRole\s*\(\s*\w+\s*,\s*msg\.sender\s*\)", body):
                    guarded = True

            findings.append({
                "function": fname,
                "visibility": vis or "",
                "modifiers": header_tail.strip(),
                "sinks": matched_sinks,
                "guarded": guarded,
                "body_excerpt": body[:300],
            })
        return findings

    escalation_paths: List[Dict[str, Any]] = []

    files_scanned = 0
    for p in repo.rglob("*.sol"):
        # Skip dependencies by default
        if ("node_modules" in str(p) or "lib" in str(p)) and str(repo) not in str(p):
            continue
        files_scanned += 1
        if files_scanned > 800:
            break
        content = _read_file(p)
        if not content:
            continue
        func_hits = _find_functions_with_sinks(content)
        for f in func_hits:
            # Heuristic classification
            unprotected = (not f["guarded"]) and ("public" in f["visibility"] or "external" in f["visibility"]) 
            cls = "unprotected_sink" if unprotected else "restricted_sink"
            severity = "HIGH" if unprotected else "MEDIUM"

            # If restricted by onlyRole, annotate which role
            role_guard = None
            mrole = re.search(r"onlyRole\s*\(\s*(\w+)\s*\)", f["modifiers"]) if f["modifiers"] else None
            if mrole:
                role_guard = mrole.group(1)
                # If role is self-admin in lattice, raise severity slightly (propagation risk)
                parents = (lattice.get("role_hierarchy", {}).get(role_guard) or [])
                if role_guard in parents:
                    cls = "self_admin_guarded_sink"
                    severity = "HIGH"

            escalation_paths.append({
                "file": str(p.relative_to(repo)),
                "function": f["function"],
                "visibility": f["visibility"],
                "modifiers": f["modifiers"],
                "sinks": f["sinks"],
                "guarded": f["guarded"],
                "role_guard": role_guard,
                "classification": cls,
                "severity": severity,
            })

    # Add lattice-only risks: self-admin roles regardless of code locations
    for child, parents in (lattice.get("role_hierarchy", {}) or {}).items():
        if child in parents:
            escalation_paths.append({
                "file": None,
                "function": None,
                "visibility": None,
                "modifiers": None,
                "sinks": ["role_self_admin"],
                "guarded": True,
                "role_guard": child,
                "classification": "self_admin_role",
                "severity": "MEDIUM",
            })

    summary = {
        "files_scanned": files_scanned,
        "escalation_findings": len(escalation_paths),
        "unprotected": sum(1 for e in escalation_paths if e["classification"] == "unprotected_sink"),
        "restricted": sum(1 for e in escalation_paths if e["classification"] == "restricted_sink"),
        "self_admin": sum(1 for e in escalation_paths if "self_admin" in e["classification"]),
    }

    return json.dumps({
        "escalation_paths": escalation_paths,
        "role_lattice_summary": lattice.get("summary", {}),
        "summary": summary,
    }, indent=2)


detect_privilege_escalation = function_tool(_detect_privilege_escalation)
