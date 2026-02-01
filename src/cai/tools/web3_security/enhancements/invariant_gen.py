"""
Invariant Hypothesis Generator

LLM-driven invariant inference from smart contract code.
Generates property-based invariants for fuzzing tools (Echidna, Medusa).

Based on:
- Function signatures and state variables
- Economic semantics (token balances, LP shares, collateralization ratios)
- Historical exploit patterns from exploit_db.jsonl
"""

import json
import re
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from cai.sdk.agents import function_tool

# Path to exploit database
EXPLOIT_DB_PATH = Path(__file__).parent.parent / "data" / "exploit_db.jsonl"


def _load_exploit_patterns() -> List[Dict[str, Any]]:
    """Load historical exploit patterns from database."""
    patterns = []

    if not EXPLOIT_DB_PATH.exists():
        return patterns

    try:
        with open(EXPLOIT_DB_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        patterns.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Warning: Could not load exploit DB: {e}")

    return patterns


def _extract_state_variables(code: str) -> List[Dict[str, str]]:
    """Extract state variables from Solidity code."""
    variables = []

    # Pattern for state variable declarations
    pattern = r"(?:\s*(public|private|internal|external)?\s*(?:uint(?:8|16|24|32|64|128|256)?\s*|int(?:8|16|24|32|64|128|256)?\s*|address|bool|string|bytes(?:\d+)?|mapping\s*\([^)]+\))\s+(\w+)"

    for match in re.finditer(pattern, code):
        var_type = match.group(1) if match.group(1) else "uint256"
        var_name = match.group(2)
        variables.append(
            {
                "name": var_name,
                "type": var_type,
            }
        )

    return variables


def _extract_functions(code: str) -> List[Dict[str, Any]]:
    """Extract function signatures from Solidity code."""
    functions = []

    # Pattern for function definitions
    pattern = r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|private|internal|external)?\s*(?:view|pure|payable)?"

    for match in re.finditer(pattern, code):
        func_name = match.group(1)
        params = match.group(2)

        functions.append(
            {
                "name": func_name,
                "params": params,
            }
        )

    return functions


def _detect_contract_type(code: str, state_vars: List[Dict[str, str]]) -> str:
    """Detect contract type based on patterns."""
    code_lower = code.lower()

    if any(v["name"] in ["totalSupply", "balanceOf", "allowance"] for v in state_vars):
        return "token"
    elif any(
        v["name"] in ["totalAssets", "totalShares", "sharePrice", "deposit", "withdraw"]
        for v in state_vars
    ):
        return "vault"
    elif any(
        v["name"] in ["healthFactor", "collateral", "borrow", "liquidate"]
        for v in state_vars
    ):
        return "lending"
    elif any(
        v["name"] in ["reserve0", "reserve1", "price0", "price1"] for v in state_vars
    ):
        return "dex"
    elif any(
        v["name"] in ["proposer", "voter", "proposalId", "execute"] for v in state_vars
    ):
        return "governance"
    else:
        return "generic"


def _match_exploit_patterns(
    contract_type: str, code_snippets: List[str]
) -> List[Dict[str, Any]]:
    """Match code against historical exploit patterns."""
    exploit_patterns = _load_exploit_patterns()
    matched = []

    for pattern in exploit_patterns:
        # Skip patterns that don't match contract type
        if contract_type not in pattern.get("category", "").lower():
            continue

        # Check for code signature matches
        for snippet in code_snippets:
            for sig in pattern.get("code_signatures", []):
                if sig.lower() in snippet.lower():
                    matched.append(
                        {
                            "exploit": pattern.get("exploit_name"),
                            "pattern": pattern,
                            "matched_signature": sig,
                            "prevention": pattern.get("negative_patterns", []),
                        }
                    )
                    break

    return matched


def _generate_balance_invariants(state_vars: List[Dict[str, str]]) -> List[str]:
    """Generate balance-related invariants."""
    invariants = []

    # Total supply consistency
    if any("totalSupply" in v["name"] for v in state_vars):
        invariants.append(
            "invariant totalSupply_balanceConsistency(uint256 amount) "
            "totalSupply() == sum_of_all_balances"
        )

    # Balance non-negative
    if any("balance" in v["name"].lower() for v in state_vars):
        invariants.append(
            "invariant balanceNonNegative(address account) balanceOf(account) >= 0"
        )

    # Total assets in vault
    if any("totalAssets" in v["name"] for v in state_vars):
        invariants.append(
            "invariant totalAssetsInvariant(address account) "
            "totalAssets() >= sum_of_user_balances"
        )

    return invariants


def _generate_share_invariants(state_vars: List[Dict[str, str]]) -> List[str]:
    """Generate share-related invariants (vaults)."""
    invariants = []

    # Total shares consistency
    if any("totalShares" in v["name"] for v in state_vars):
        invariants.append(
            "invariant totalSharesConsistency(address account) "
            "totalShares() == sum_of_all_user_shares"
        )

    # Share price monotonicity (should not decrease unexpectedly)
    invariants.append(
        "invariant sharePriceNeverDecreasesUnexpectedly() "
        "for all blocks, sharePrice(t) >= sharePrice(t-1) or deposit_withdraw_occurred"
    )

    # Asset share equivalence
    invariants.append(
        "invariant assetShareEquivalence() "
        "totalAssets() * totalShares(t-1) == totalAssets(t-1) * totalShares()"
    )

    return invariants


def _generate_collateral_invariants(state_vars: List[Dict[str, str]]) -> List[str]:
    """Generate collateral/lending invariants."""
    invariants = []

    # Health factor above minimum
    invariants.append(
        "invariant healthFactorAboveMinimum(address borrower) "
        "healthFactor(borrower) >= MIN_HEALTH_FACTOR"
    )

    # Collateralization ratio
    if any("collateral" in v["name"].lower() for v in state_vars):
        invariants.append(
            "invariant collateralizationRatio(address position) "
            "collateralValue(position) >= borrowedAmount(position) * MIN_COLLATERAL_RATIO"
        )

    # Total supply covers liabilities
    if any("totalBorrows" in v["name"] or "totalDebt" in v["name"] for v in state_vars):
        invariants.append("invariant solvencyInvariant() totalSupply >= totalDebt")

    return invariants


def _generate_oracle_invariants(
    code: str, state_vars: List[Dict[str, str]]
) -> List[str]:
    """Generate oracle-related invariants."""
    invariants = []
    code_lower = code.lower()

    # Oracle staleness
    if (
        "oracle" in code_lower
        or "getprice" in code_lower
        or "getreserves" in code_lower
    ):
        invariants.append(
            "invariant oracleFreshness() "
            "block.timestamp - oracle.updatedAt() < MAX_STALENESS_SECONDS"
        )

    # Price within bounds
    if "price" in code_lower:
        invariants.append(
            "invariant priceWithinBounds(uint256 price) "
            "price > 0 && price < MAX_REASONABLE_PRICE"
        )

    # TWAP usage over spot price
    if "getreserves" in code_lower or "pricecumulativelast" in code_lower:
        invariants.append(
            "invariant twapOverSpotPrice() "
            "observedPrice >= min(price_cumulative / time_window, current_spot)"
        )

    return invariants


def _generate_access_control_invariants(code: str) -> List[str]:
    """Generate access control invariants."""
    invariants = []
    code_lower = code.lower()

    # Only owner/admin can call privileged functions
    privileged_patterns = [
        r"function\s+(mint|burn|pause|unpause|withdrawall|setconfig)\s*\(",
        r"function\s+(transferownership|renounceownership)\s*\(",
        r"function\s+(upgrade|setimplementation)\s*\(",
    ]

    for pattern in privileged_patterns:
        if re.search(pattern, code_lower):
            func_match = re.search(r"function\s+(\w+)", pattern)
            if func_match:
                func_name = func_match.group(1)
                invariants.append(
                    f"invariant onlyAuthorizedCan{func_name[0].upper() + func_name[1:]}() "
                    f"msg.sender == owner || msg.sender == admin || hasRole(msg.sender, {func_name.upper()}_ROLE)"
                )

    return invariants


def _generate_reentrancy_invariants(code: str) -> List[str]:
    """Generate reentrancy protection invariants."""
    invariants = []
    code_lower = code.lower()

    # Check for external calls before state updates
    if ".call(" in code_lower or ".transfer(" in code_lower:
        invariants.append(
            "invariant stateUpdatesBeforeExternalCalls() "
            "for all functions, state_changes_occur_before_external_calls"
        )

    # Non-reentrant modifier usage
    if ".call(" in code_lower and "nonreentrant" not in code_lower:
        invariants.append(
            "invariant reentrancyProtected() "
            "functions_with_external_calls have nonReentrant modifier"
        )

    return invariants


@function_tool
def generate_invariants(
    contract_code: str,
    contract_type: str = "auto",
    include_historical_patterns: bool = True,
    ctf=None,
) -> str:
    """
    Generate property-based invariants for smart contract fuzzing.

    Analyzes contract code and generates invariants based on:
    - State variables and their relationships
    - Contract type (token, vault, lending, dex, governance)
    - Historical exploit patterns (if enabled)

    Args:
        contract_code: Solidity source code of the contract
        contract_type: Contract type (auto, token, vault, lending, dex, governance)
        include_historical_patterns: Whether to use exploit DB for pattern matching

    Returns:
        JSON string with generated invariants and metadata
    """
    try:
        # Extract contract structure
        state_vars = _extract_state_variables(contract_code)
        functions = _extract_functions(contract_code)

        # Detect contract type if not specified
        if contract_type == "auto":
            contract_type = _detect_contract_type(contract_code, state_vars)

        # Generate invariants by category
        invariants = []
        invariant_sources = []

        # Balance invariants
        balance_invs = _generate_balance_invariants(state_vars)
        if balance_invs:
            invariants.extend(balance_invs)
            invariant_sources.extend(["balance_analysis"] * len(balance_invs))

        # Share invariants (vaults)
        if contract_type == "vault":
            share_invs = _generate_share_invariants(state_vars)
            invariants.extend(share_invs)
            invariant_sources.extend(["share_analysis"] * len(share_invs))

        # Collateral invariants (lending)
        if contract_type == "lending":
            collateral_invs = _generate_collateral_invariants(state_vars)
            invariants.extend(collateral_invs)
            invariant_sources.extend(["collateral_analysis"] * len(collateral_invs))

        # Oracle invariants
        oracle_invs = _generate_oracle_invariants(contract_code, state_vars)
        if oracle_invs:
            invariants.extend(oracle_invs)
            invariant_sources.extend(["oracle_analysis"] * len(oracle_invs))

        # Access control invariants
        access_invs = _generate_access_control_invariants(contract_code)
        if access_invs:
            invariants.extend(access_invs)
            invariant_sources.extend(["access_control"] * len(access_invs))

        # Reentrancy invariants
        reentrancy_invs = _generate_reentrancy_invariants(contract_code)
        if reentrancy_invs:
            invariants.extend(reentrancy_invs)
            invariant_sources.extend(["reentrancy_analysis"] * len(reentrancy_invs))

        # Match against historical exploit patterns
        exploit_matches = []
        if include_historical_patterns:
            code_snippets = [
                contract_code[max(0, i - 500) : i + 500]
                for i in range(0, len(contract_code), 500)
            ]
            exploit_matches = _match_exploit_patterns(contract_type, code_snippets)
            if exploit_matches:
                # Generate invariants from negative patterns
                for match in exploit_matches:
                    for prevention in match.get("prevention", []):
                        # Convert prevention pattern to invariant
                        if "TWAP" in prevention or "twap" in prevention.lower():
                            invariants.append(
                                f"invariant twapPriceProtection() "
                                f"price_observed >= twap_calculation"
                            )
                        elif (
                            "nonReentrant" in prevention
                            or "reentrancy" in prevention.lower()
                        ):
                            invariants.append(
                                "invariant noReentrancyInFunctions() "
                                "functions_with_callbacks have reentrancy guards"
                            )
                        elif "require(amount > 0)" in prevention:
                            invariants.append(
                                "invariant positiveAmounts(address account, uint256 amount) "
                                "amount >= 0"
                            )

                invariant_sources.extend(
                    ["historical_pattern_matching"] * len(exploit_matches)
                )

        # Prepare output
        output = {
            "contract_type": contract_type,
            "state_variables": len(state_vars),
            "functions": len(functions),
            "invariants": invariants,
            "total_invariants": len(invariants),
            "invariant_sources": invariant_sources,
            "exploit_matches": len(exploit_matches),
            "recommendations": [
                f"Add invariants to Echidna config for {contract_type} contracts",
                f"Use Medusa with property: {invariants[0] if invariants else 'custom'}",
                "Focus testing on functions with external calls",
            ],
        }

        return json.dumps(output, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Error generating invariants: {str(e)}"})


@function_tool
def generate_echidna_config(
    invariants: str,
    output_path: str = "echidna.yaml",
    test_limit: int = 50000,
    ctf=None,
) -> str:
    """
    Generate Echidna configuration file from invariants.

    Takes invariants generated by generate_invariants and produces
    a valid Echidna YAML configuration file.

    Args:
        invariants: JSON string from generate_invariants output
        output_path: Path for the generated config file
        test_limit: Number of test sequences to run

    Returns:
        JSON string with config file path and status
    """
    try:
        inv_data = json.loads(invariants) if isinstance(invariants, str) else invariants
        inv_list = inv_data.get("invariants", [])

        # Build Echidna config
        config_lines = [
            "testMode: assertion",
            f"testLimit: {test_limit}",
            "testLimit: 50000",
            "assertion: testing_1:",
            "  -:",
            f"    - contract: $TARGET_CONTRACT",
            "    - invariant:",
        ]

        # Add invariants
        for inv in inv_list:
            # Format: "invariant functionName(args) property"
            if "invariant" in inv:
                # Extract the property part
                parts = inv.split("invariant", 1)[1].strip()
                func_part = parts.split("(", 1)[0].strip()
                prop_part = parts.split(")", 1)[1].strip() if ")" in parts else ""

                config_lines.append(f"        {prop_part}")
                config_lines.append("  -:")
                config_lines.append(f"    - contract: $TARGET_CONTRACT")
                config_lines.append(f"    - invariant: {prop_part}")

        # Write config file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(config_lines))

        return json.dumps(
            {
                "status": "success",
                "config_file": output_path,
                "invariants_included": len(inv_list),
                "test_limit": test_limit,
                "usage": f"echidna --contract $TARGET_CONTRACT --config {output_path}",
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error generating Echidna config: {str(e)}"})


@function_tool
def generate_medusa_config(
    invariants: str, output_path: str = "medusa.yaml", workers: int = 4, ctf=None
) -> str:
    """
    Generate Medusa configuration file from invariants.

    Takes invariants generated by generate_invariants and produces
    a valid Medusa YAML configuration file.

    Args:
        invariants: JSON string from generate_invariants output
        output_path: Path for the generated config file
        workers: Number of parallel workers for fuzzing

    Returns:
        JSON string with config file path and status
    """
    try:
        inv_data = json.loads(invariants) if isinstance(invariants, str) else invariants
        inv_list = inv_data.get("invariants", [])

        # Build Medusa config
        config_lines = [
            "medusa:",
            f"  workers: {workers}",
            "  test-arguments:",
            "    - '-c config.yaml'",
            "    - '--parallel'",
            "    - '-g 2'",
            "  test-limit: 10000",
            "  corpus-dir: corpus/",
            "  crytic-args: '--allowPaths'",
            "  deployment-args: '--constructor-args' ' '",
            "  send-tx:",
            "  fuzzing-params:",
            "  assertions:",
        ]

        # Add invariants as assertions
        for inv in inv_list:
            if "invariant" in inv:
                # Extract property part
                parts = inv.split("invariant", 1)[1].strip()
                prop_part = parts.split(")", 1)[1].strip() if ")" in parts else ""

                config_lines.append(f"    - {prop_part}")

        # Write config file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(config_lines))

        return json.dumps(
            {
                "status": "success",
                "config_file": output_path,
                "invariants_included": len(inv_list),
                "workers": workers,
                "usage": f"medusa -c {output_path} $TARGET_CONTRACT",
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error generating Medusa config: {str(e)}"})
