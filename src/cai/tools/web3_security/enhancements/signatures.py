import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
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

def _analyze_eip712_implementation(content: str, filename: str) -> List[Dict[str, Any]]:
    """Analyze Solidity content for EIP-712 Domain Separator issues."""
    findings = []
    
    # 1. Identify contract name(s) in the file
    contract_matches = re.finditer(r"contract\s+(\w+)", content)
    for contract_match in contract_matches:
        contract_name = contract_match.group(1)
        
        # Find the contract body (very rough estimation)
        # This is a heuristic to bound our search within the contract
        start_pos = contract_match.start()
        # Find the next contract or end of file
        next_contract = re.search(r"contract\s+\w+", content[start_pos + 1:])
        end_pos = start_pos + next_contract.start() if next_contract else len(content)
        contract_body = content[start_pos:end_pos]
        
        # Check if EIP-712 is used (keywords)
        if not any(x in contract_body for x in ["DOMAIN_SEPARATOR", "EIP712", "eip712Domain", "EIP-712"]):
            continue
            
        # 2. Check for Domain Separator calculation
        # Look for the calculation of the domain separator
        # Pattern: keccak256(abi.encode(...)
        
        # Heuristic for Domain Separator construction
        has_domain_separator = "DOMAIN_SEPARATOR" in contract_body
        uses_chainid = "block.chainid" in contract_body or "chainid()" in contract_body
        uses_this = "address(this)" in contract_body
        
        # 3. Check for Caching Vulnerability (Common in EIP-712)
        # Many contracts cache the domain separator in an immutable or constant variable
        # but fail to re-calculate it if block.chainid changes (e.g. after a hard fork).
        
        is_cached_immutable = re.search(r"bytes32\s+public\s+immutable\s+[\w_]*DOMAIN_SEPARATOR", contract_body)
        is_cached_constant = re.search(r"bytes32\s+public\s+constant\s+[\w_]*DOMAIN_SEPARATOR", contract_body)
        
        # If it's cached, check if there's a fallback re-calculation
        has_recalculation = False
        if is_cached_immutable or is_cached_constant:
            # Look for logic that checks if the current chainId matches the one used for the cached separator
            # e.g. if (block.chainid == _cachedChainId) return _cachedDomainSeparator;
            if "block.chainid" in contract_body and ("==" in contract_body or "!=" in contract_body):
                has_recalculation = True
        
        # 4. Generate findings based on heuristics
        
        # Missing ChainID (Critical Replay Risk)
        if has_domain_separator and not uses_chainid:
            findings.append({
                "contract": contract_name,
                "file": filename,
                "issue": "Missing chainID in DOMAIN_SEPARATOR",
                "severity": "HIGH",
                "description": "The DOMAIN_SEPARATOR does not appear to include block.chainid. This allows signatures to be replayed across different chains (e.g., from Mainnet to L2s or after a hard fork).",
                "recommendation": "Include block.chainid in the EIP-712 domain separator calculation."
            })
            
        # Missing address(this) (Contract Replay Risk)
        if has_domain_separator and not uses_this:
            findings.append({
                "contract": contract_name,
                "file": filename,
                "issue": "Missing address(this) in DOMAIN_SEPARATOR",
                "severity": "MEDIUM",
                "description": "The DOMAIN_SEPARATOR does not appear to include address(this). This might allow signatures intended for one contract to be replayed on another contract with the same name and version.",
                "recommendation": "Include address(this) in the EIP-712 domain separator calculation."
            })
            
        # Improper caching (Fork Replay Risk)
        if (is_cached_immutable or is_cached_constant) and not has_recalculation and uses_chainid:
             findings.append({
                "contract": contract_name,
                "file": filename,
                "issue": "Vulnerable DOMAIN_SEPARATOR caching",
                "severity": "MEDIUM",
                "description": "The DOMAIN_SEPARATOR is cached in an immutable or constant variable without re-calculating it when block.chainid changes. This can lead to signature replay attacks after a chain hard fork.",
                "recommendation": "Use OpenZeppelin's EIP712 implementation or implement a check that re-calculates the domain separator if block.chainid != cachedChainId."
            })
            
    return findings

def _validate_domain_separator(repo_path: str, ctf=None) -> str:
    """
    Validate EIP-712 Domain Separator implementations in a smart contract repository.
    
    This tool performs Domain Separator Validation by checking:
    1. ChainID Binding: Does the domain separator include block.chainid to prevent cross-chain replays?
    2. Address Binding: Does it include address(this) to prevent cross-contract replays?
    3. Fork Safety: Is the domain separator re-calculated if block.chainid changes (caching protection)?
    
    Args:
        repo_path: Path to the repository root to scan.
        
    Returns:
        JSON string containing the results of the EIP-712 domain separator validation.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)
    
    all_findings = []
    files_scanned = 0
    
    # Scan for Solidity files
    for p in repo.rglob("*.sol"):
        # Skip node_modules and lib by default unless they are the target
        if "node_modules" in str(p) or "lib" in str(p):
            if repo_path not in str(p):
                continue
                
        files_scanned += 1
        if files_scanned > 800: break # Safety limit
            
        content = _read_file(p)
        if not content: continue
        
        # Quick check for relevant keywords to avoid deep analysis of every file
        if not any(x in content for x in ["DOMAIN_SEPARATOR", "EIP712", "eip712Domain", "EIP-712"]):
            continue
            
        file_findings = _analyze_eip712_implementation(content, str(p.relative_to(repo)))
        all_findings.extend(file_findings)
        
    summary = {
        "total_files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "high_severity": len([f for f in all_findings if f["severity"] == "HIGH"]),
        "medium_severity": len([f for f in all_findings if f["severity"] == "MEDIUM"])
    }
    
    return json.dumps({
        "findings": all_findings,
        "summary": summary
    }, indent=2)

def _analyze_nonce_replay_implementation(content: str, filename: str) -> List[Dict[str, Any]]:
    """Analyze Solidity content for signature-based nonce/replay issues."""
    findings = []
    
    # Identify contract name(s)
    contract_matches = re.finditer(r"contract\s+(\w+)", content)
    for contract_match in contract_matches:
        contract_name = contract_match.group(1)
        
        # Heuristic contract body
        start_pos = contract_match.start()
        next_contract = re.search(r"contract\s+\w+", content[start_pos + 1:])
        end_pos = start_pos + next_contract.start() if next_contract else len(content)
        contract_body = content[start_pos:end_pos]
        
        # Check for signature keywords
        if not any(x in contract_body for x in ["ecrecover", ".recover(", "permit", "Signature"]):
            continue
            
        # Find all function definitions
        # This regex is a simple heuristic for function headers
        function_matches = re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)\s*([^\{]*)", contract_body)
        for func_match in function_matches:
            func_name = func_match.group(1)
            func_params = func_match.group(2)
            func_header_end = func_match.end()
            
            # Find function body (very rough)
            # Find the first { after header, then find its matching }
            body_start = contract_body.find("{", func_header_end)
            if body_start == -1: continue
            
            # Count braces to find the end of the function body
            brace_count = 1
            body_end = body_start + 1
            while brace_count > 0 and body_end < len(contract_body):
                if contract_body[body_end] == "{": brace_count += 1
                elif contract_body[body_end] == "}": brace_count -= 1
                body_end += 1
            
            func_body = contract_body[body_start:body_end]
            
            # Check for signature verification in this function
            has_sig_verify = "ecrecover" in func_body or ".recover(" in func_body
            if not has_sig_verify: continue
            
            # 1. Nonce check
            # Pattern: nonces[owner]++ or _useNonce(owner)
            has_nonce_management = "nonces" in func_body and ("++" in func_body or "+=" in func_body or "=" in func_body)
            has_use_nonce = "_useNonce" in func_body or "useNonce" in func_body
            
            if not (has_nonce_management or has_use_nonce):
                findings.append({
                    "contract": contract_name,
                    "function": func_name,
                    "file": filename,
                    "issue": "Missing Nonce Management in Signature Verification",
                    "severity": "HIGH",
                    "description": f"The function '{func_name}' appears to verify a signature but doesn't appear to update or check a nonce. This might allow an attacker to replay the same signature multiple times.",
                    "recommendation": "Implement a nonce tracking mechanism (e.g., mapping(address => uint256) nonces) to prevent replay attacks."
                })
                
            # 2. Deadline check
            # Look for variables like deadline, expiry, expires, validUntil
            has_deadline_param = any(x in func_params.lower() for x in ["deadline", "expiry", "expires", "validuntil"])
            has_timestamp_check = "block.timestamp" in func_body or "now" in func_body
            
            # Heuristic for missing deadline enforcement
            if has_deadline_param and not (has_timestamp_check and (">" in func_body or "<" in func_body)):
                 findings.append({
                    "contract": contract_name,
                    "function": func_name,
                    "file": filename,
                    "issue": "Unchecked Signature Deadline",
                    "severity": "MEDIUM",
                    "description": f"The function '{func_name}' takes a deadline/expiry parameter but does not appear to check it against 'block.timestamp'. This could allow signatures to be executed after they were intended to expire.",
                    "recommendation": "Enforce that block.timestamp <= deadline or similar."
                })
            elif not has_deadline_param and not (has_nonce_management or has_use_nonce):
                # If no nonce and no deadline, it's a critical replay risk
                # But we already added the HIGH nonce finding. 
                # Let's add a note about deadline if both are missing.
                pass

    return findings

def _analyze_nonce_replay(repo_path: str, ctf=None) -> str:
    """
    Model off-chain message state to find signature reuse vulnerabilities.
    
    This tool performs Nonce/Replay Analysis by checking:
    1. Nonce Management: Does signature verification update a nonce to prevent reuse?
    2. Deadline Enforcement: Are off-chain messages protected by an expiry window?
    3. Replayability: Identifying paths where the same signature can be re-executed.
    
    Args:
        repo_path: Path to the repository root to scan.
        
    Returns:
        JSON string containing the results of the nonce/replay analysis.
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)
    
    all_findings = []
    files_scanned = 0
    
    # Scan for Solidity files
    for p in repo.rglob("*.sol"):
        # Skip node_modules and lib by default unless they are the target
        if "node_modules" in str(p) or "lib" in str(p):
            if repo_path not in str(p):
                continue
                
        files_scanned += 1
        if files_scanned > 800: break # Safety limit
            
        content = _read_file(p)
        if not content: continue
        
        # Quick check for relevant keywords
        if not any(x in content for x in ["ecrecover", ".recover(", "permit", "Signature"]):
            continue
            
        file_findings = _analyze_nonce_replay_implementation(content, str(p.relative_to(repo)))
        all_findings.extend(file_findings)
        
    summary = {
        "total_files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "high_severity": len([f for f in all_findings if f["severity"] == "HIGH"]),
        "medium_severity": len([f for f in all_findings if f["severity"] == "MEDIUM"])
    }
    
    return json.dumps({
        "findings": all_findings,
        "summary": summary
    }, indent=2)

def _analyze_permit_flows_implementation(content: str, filename: str) -> List[Dict[str, Any]]:
    """Model EIP-2612 permit flows and allowance races.

    Heuristics covered:
    - Permit deadline enforcement: presence of `deadline` param and `block.timestamp` check
    - Permit nonce usage: `nonces[owner]++` or `_useNonce(owner)` (complementary to nonce tool)
    - Allowance race in ERC20 `approve`: changing non-zero to non-zero without zero-reset guard
    - Atomicity risk in dApps/contracts using `permit(...)` and `transferFrom(...)` in separate funcs
    """
    findings: List[Dict[str, Any]] = []

    # Identify contract name(s)
    for c_match in re.finditer(r"contract\s+(\w+)", content):
        contract_name = c_match.group(1)
        start_pos = c_match.start()
        next_c = re.search(r"contract\s+\w+", content[start_pos + 1:])
        end_pos = start_pos + next_c.start() if next_c else len(content)
        body = content[start_pos:end_pos]

        # --- Detect ERC20 approve race (non-zero to non-zero without zero-first guard) ---
        if "function approve" in body or ".approve(" in body:
            # Look for a zero-reset guard pattern in approve implementation
            # Common safe pattern: require(value == 0 || allowance[owner][spender] == 0)
            approve_impl_match = re.search(r"function\s+approve\s*\([^)]*\)\s*([^{]*)\{([\s\S]*?)\}", body)
            approve_body = approve_impl_match.group(2) if approve_impl_match else ""
            has_zero_reset_guard = bool(re.search(r"require\s*\(\s*([\w\[\]\.]*)\s*==\s*0\s*\|\|\s*([\w\[\]\.]*)\s*==\s*0\s*\)", approve_body))
            if approve_impl_match and not has_zero_reset_guard:
                findings.append({
                    "contract": contract_name,
                    "file": filename,
                    "issue": "ERC20 approve race (no zero-first guard)",
                    "severity": "MEDIUM",
                    "description": "`approve` may allow spender front-running when changing from non-zero to non-zero without first setting allowance to 0.",
                    "recommendation": "Enforce zero-first pattern or use increaseAllowance/decreaseAllowance APIs."
                })

        # --- Detect EIP-2612 permit implementation quality ---
        # Find a permit function signature heuristically
        for pm in re.finditer(r"function\s+permit\s*\(([^)]*)\)\s*([^{]*)\{([\s\S]*?)\}", body, re.IGNORECASE):
            params = pm.group(1)
            header = pm.group(2)
            fbody = pm.group(3)
            # Check presence of typical params
            has_deadline_param = any(x in params.lower() for x in ["deadline", "expiry", "validuntil"]) 
            has_sig_params = ("v" in params and "r" in params and "s" in params) or "bytes" in params.lower()
            # Deadline enforcement
            has_deadline_enforcement = ("block.timestamp" in fbody or "now" in fbody) and (">" in fbody or "<" in fbody)
            if has_deadline_param and not has_deadline_enforcement:
                findings.append({
                    "contract": contract_name,
                    "file": filename,
                    "function": "permit",
                    "issue": "Permit missing deadline enforcement",
                    "severity": "HIGH",
                    "description": "`permit` defines a deadline/expiry but does not enforce it against `block.timestamp`.",
                    "recommendation": "Add `require(block.timestamp <= deadline, \"PERMIT_DEADLINE_EXPIRED\")`."
                })
            # Nonce usage
            has_nonce_mgmt = ("nonces" in fbody and ("++" in fbody or "+=" in fbody or re.search(r"nonces\s*\[", fbody))) or ("_useNonce" in fbody or "useNonce" in fbody)
            if has_sig_params and not has_nonce_mgmt:
                findings.append({
                    "contract": contract_name,
                    "file": filename,
                    "function": "permit",
                    "issue": "Permit missing nonce management",
                    "severity": "HIGH",
                    "description": "`permit` verifies signature but does not appear to consume a unique nonce, enabling replay.",
                    "recommendation": "Maintain `nonces[owner]` and increment/consume on use, or `_useNonce(owner)`."
                })
            # Allowance set pattern (ok either set or increase). Just informational if allowance not set
            if not re.search(r"allowance\s*\[|_approve\s*\(|_spendAllowance\s*\(", fbody):
                findings.append({
                    "contract": contract_name,
                    "file": filename,
                    "function": "permit",
                    "issue": "Permit does not update allowance",
                    "severity": "LOW",
                    "description": "`permit` present but does not appear to update allowance (may be a custom usage).",
                    "recommendation": "Confirm intended semantics or wire to `_approve(owner, spender, value)` per EIP-2612."
                })

        # --- Atomicity risk: permit/transferFrom split across functions ---
        funcs_calling_permit = [m.group(1) for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}", body) if ".permit(" in (m.group(2) if m else "")]
        funcs_calling_tf = [m.group(1) for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}", body) if ".transferFrom(" in (m.group(2) if m else "")]
        # If there exists a function that calls permit but none that also calls transferFrom in the same body,
        # and there is at least one function calling transferFrom elsewhere, flag atomicity risk.
        if funcs_calling_permit and funcs_calling_tf:
            both_in_same = False
            for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}", body):
                fname = m.group(1)
                fbody2 = m.group(2)
                if ".permit(" in fbody2 and ".transferFrom(" in fbody2:
                    both_in_same = True
                    break
            if not both_in_same:
                findings.append({
                    "contract": contract_name,
                    "file": filename,
                    "issue": "Permit then transferFrom split across functions (atomicity/race risk)",
                    "severity": "MEDIUM",
                    "description": "`permit` and `transferFrom` are invoked in different functions, inviting front-run/reordering risk between transactions.",
                    "recommendation": "Bundle `permit` and `transferFrom` atomically in the same function (EIP-2612 meta-transaction style)."
                })

    return findings


def _analyze_permit_flows(repo_path: str, ctf=None) -> str:
    """Repository-wide Permit/Allowance flow analysis.

    Returns JSON with findings across:
    - Permit deadline exploits
    - Missing nonce in permit (complements Nonce/Replay tool)
    - ERC20 approve race (non-zero → non-zero)
    - Atomicity risks splitting permit/transferFrom
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)

    all_findings: List[Dict[str, Any]] = []
    files_scanned = 0

    for p in repo.rglob("*.sol"):
        if "node_modules" in str(p) or "lib" in str(p):
            if repo_path not in str(p):
                continue
        files_scanned += 1
        if files_scanned > 800:
            break
        content = _read_file(p)
        if not content:
            continue
        # Skip quickly if not relevant
        if not any(x in content for x in [" permit(", ".permit(", "transferFrom(", "approve(", "nonces["]):
            continue
        all_findings.extend(_analyze_permit_flows_implementation(content, str(p.relative_to(repo))))

    summary = {
        "total_files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "high_severity": len([f for f in all_findings if f.get("severity") == "HIGH"]),
        "medium_severity": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
        "low_severity": len([f for f in all_findings if f.get("severity") == "LOW"]),
    }

    return json.dumps({
        "findings": all_findings,
        "summary": summary,
    }, indent=2)


validate_domain_separator = function_tool(_validate_domain_separator)
analyze_nonce_replay = function_tool(_analyze_nonce_replay)
analyze_permit_flows = function_tool(_analyze_permit_flows)
