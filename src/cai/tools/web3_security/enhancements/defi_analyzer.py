"""
DeFi Protocol Analysis Module

This module provides specialized analysis for DeFi protocol vulnerabilities
including oracle manipulation, flash loan attacks, MEV exposure, and more.
"""

import json
import re
from typing import Any, Dict, List, Optional
from cai.sdk.agents import function_tool


# Oracle patterns to detect
ORACLE_PATTERNS = {
    "chainlink": {
        "patterns": [r"AggregatorV3Interface", r"latestRoundData", r"getRoundData"],
        "staleness_check": r"updatedAt",
        "price_check": r"answer\s*[><=]",
    },
    "uniswap_v2": {
        "patterns": [r"getReserves", r"price0CumulativeLast", r"price1CumulativeLast"],
        "twap_check": r"observe|consult",
    },
    "uniswap_v3": {
        "patterns": [r"slot0", r"observe", r"snapshotCumulativesInside"],
        "twap_check": r"secondsAgo",
    },
    "custom": {
        "patterns": [r"getPrice", r"latestPrice", r"oracle\."],
    },
}

# Flash loan provider patterns
FLASH_LOAN_PATTERNS = {
    "aave": [r"flashLoan", r"FLASHLOAN_PREMIUM", r"executeOperation"],
    "dydx": [r"SoloMargin", r"callFunction", r"AccountInfo"],
    "uniswap_v3": [r"flash\(", r"uniswapV3FlashCallback"],
    "balancer": [r"flashLoan", r"receiveFlashLoan"],
    "maker": [r"daiJoin", r"vat\."],
}


def _find_patterns(code: str, patterns: List[str]) -> List[Dict[str, Any]]:
    """Find all occurrences of patterns in code."""
    matches = []
    for pattern in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            matches.append({
                "pattern": pattern,
                "match": match.group(),
                "position": match.start(),
            })
    return matches


@function_tool
def analyze_oracle_manipulation(
    contract_code: str,
    check_staleness: bool = True,
    check_manipulation: bool = True,
    ctf=None
) -> str:
    """
    Analyze a contract for oracle manipulation vulnerabilities.
    
    Checks for:
    - Missing staleness checks on oracle data
    - Spot price usage vulnerable to manipulation
    - Missing price bounds validation
    - Single oracle dependency
    
    Args:
        contract_code: Solidity source code to analyze
        check_staleness: Check for missing staleness validation
        check_manipulation: Check for manipulation vectors
    
    Returns:
        JSON string with oracle vulnerability analysis
    """
    try:
        findings = []
        oracle_usage = []
        
        # Detect oracle types used
        for oracle_type, config in ORACLE_PATTERNS.items():
            matches = _find_patterns(contract_code, config["patterns"])
            if matches:
                oracle_usage.append({
                    "type": oracle_type,
                    "matches": len(matches),
                    "locations": matches[:5],  # First 5 matches
                })
        
        if not oracle_usage:
            return json.dumps({
                "oracle_detected": False,
                "message": "No oracle usage patterns detected in contract",
            }, indent=2)
        
        # Check for staleness issues
        if check_staleness:
            for oracle in oracle_usage:
                if oracle["type"] == "chainlink":
                    staleness_config = ORACLE_PATTERNS["chainlink"]
                    staleness_matches = _find_patterns(contract_code, [staleness_config["staleness_check"]])
                    
                    if not staleness_matches:
                        findings.append({
                            "type": "oracle-staleness",
                            "severity": "HIGH",
                            "oracle_type": "chainlink",
                            "description": "Chainlink oracle used without staleness check (updatedAt validation missing)",
                            "recommendation": "Add check: require(block.timestamp - updatedAt < MAX_STALENESS)",
                        })
                    
                    # Check for price validation
                    price_matches = _find_patterns(contract_code, [staleness_config["price_check"]])
                    if not price_matches:
                        findings.append({
                            "type": "oracle-no-bounds",
                            "severity": "MEDIUM",
                            "oracle_type": "chainlink",
                            "description": "Chainlink oracle used without price bounds validation",
                            "recommendation": "Add check: require(answer > 0 && answer < MAX_PRICE)",
                        })
                
                if oracle["type"] in ["uniswap_v2", "uniswap_v3"]:
                    twap_config = ORACLE_PATTERNS[oracle["type"]]
                    twap_matches = _find_patterns(contract_code, [twap_config.get("twap_check", "")])
                    
                    if not twap_matches:
                        findings.append({
                            "type": "spot-price-usage",
                            "severity": "CRITICAL",
                            "oracle_type": oracle["type"],
                            "description": f"{oracle['type']} spot price used without TWAP - vulnerable to flash loan manipulation",
                            "recommendation": "Use TWAP oracle with sufficient observation window (e.g., 30 minutes)",
                        })
        
        # Check for manipulation vectors
        if check_manipulation:
            # Check for single oracle dependency
            if len(oracle_usage) == 1:
                findings.append({
                    "type": "single-oracle-dependency",
                    "severity": "MEDIUM",
                    "description": "Contract relies on a single oracle source",
                    "recommendation": "Consider using multiple oracle sources with median/fallback logic",
                })
            
            # Check for getReserves without TWAP (Uniswap V2 manipulation)
            if any(o["type"] == "uniswap_v2" for o in oracle_usage):
                reserves_matches = _find_patterns(contract_code, [r"getReserves"])
                twap_matches = _find_patterns(contract_code, [r"price\d?CumulativeLast"])
                
                if reserves_matches and not twap_matches:
                    findings.append({
                        "type": "uniswap-v2-manipulation",
                        "severity": "CRITICAL",
                        "description": "Using getReserves() for price without TWAP - easily manipulated with flash loans",
                        "recommendation": "Use price0CumulativeLast/price1CumulativeLast with time-weighted average",
                    })
        
        return json.dumps({
            "oracle_detected": True,
            "oracles_found": oracle_usage,
            "findings": findings,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing oracle manipulation: {str(e)}"})


@function_tool
def analyze_flash_loan_vectors(
    contract_code: str,
    check_callbacks: bool = True,
    ctf=None
) -> str:
    """
    Analyze a contract for flash loan attack vectors.
    
    Checks for:
    - Flash loan callback implementations
    - State changes vulnerable to flash loan manipulation
    - Missing flash loan protection patterns
    
    Args:
        contract_code: Solidity source code to analyze
        check_callbacks: Check for flash loan callback implementations
    
    Returns:
        JSON string with flash loan vulnerability analysis
    """
    try:
        findings = []
        flash_loan_usage = []
        
        # Detect flash loan patterns
        for provider, patterns in FLASH_LOAN_PATTERNS.items():
            matches = _find_patterns(contract_code, patterns)
            if matches:
                flash_loan_usage.append({
                    "provider": provider,
                    "matches": len(matches),
                    "locations": matches[:3],
                })
        
        # Check for vulnerable patterns
        vulnerable_patterns = [
            {
                "pattern": r"balanceOf\([^)]+\)\s*[><=]",
                "type": "balance-check-manipulation",
                "severity": "HIGH",
                "description": "Balance check that could be manipulated during flash loan",
            },
            {
                "pattern": r"totalSupply\(\)\s*[><=]",
                "type": "supply-check-manipulation",
                "severity": "MEDIUM",
                "description": "Total supply check that could be affected by flash minting",
            },
            {
                "pattern": r"getReserves\(\)",
                "type": "reserve-manipulation",
                "severity": "CRITICAL",
                "description": "DEX reserves check vulnerable to flash loan manipulation",
            },
        ]
        
        for vuln in vulnerable_patterns:
            matches = _find_patterns(contract_code, [vuln["pattern"]])
            if matches:
                findings.append({
                    "type": vuln["type"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "matches": len(matches),
                    "recommendation": "Add flash loan protection or use TWAP/time-delayed values",
                })
        
        # Check for callback implementations
        if check_callbacks:
            callback_patterns = [
                r"executeOperation",  # Aave
                r"uniswapV3FlashCallback",  # Uniswap V3
                r"receiveFlashLoan",  # Balancer
                r"callFunction",  # dYdX
            ]
            
            for pattern in callback_patterns:
                matches = _find_patterns(contract_code, [pattern])
                if matches:
                    # Check if callback has proper validation
                    # This is simplified - real analysis would check the full function
                    findings.append({
                        "type": "flash-loan-callback",
                        "severity": "INFO",
                        "description": f"Flash loan callback '{pattern}' detected - verify proper validation",
                        "recommendation": "Ensure callback validates initiator and loan parameters",
                    })
        
        # Check for reentrancy in flash loan context
        if flash_loan_usage:
            nonreentrant_matches = _find_patterns(contract_code, [r"nonReentrant", r"ReentrancyGuard"])
            if not nonreentrant_matches:
                findings.append({
                    "type": "flash-loan-reentrancy",
                    "severity": "HIGH",
                    "description": "Flash loan usage detected without reentrancy protection",
                    "recommendation": "Add ReentrancyGuard to flash loan callbacks and related functions",
                })
        
        return json.dumps({
            "flash_loan_detected": len(flash_loan_usage) > 0,
            "providers_found": flash_loan_usage,
            "findings": findings,
            "total_findings": len(findings),
            "attack_surface": "HIGH" if any(f["severity"] == "CRITICAL" for f in findings) else "MEDIUM" if findings else "LOW",
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing flash loan vectors: {str(e)}"})


@function_tool
def analyze_mev_exposure(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze a contract for MEV (Maximal Extractable Value) exposure.
    
    Checks for:
    - Sandwich attack vulnerabilities
    - Front-running opportunities
    - Back-running opportunities
    - Missing slippage protection
    
    Args:
        contract_code: Solidity source code to analyze
    
    Returns:
        JSON string with MEV exposure analysis
    """
    try:
        findings = []
        
        # Check for swap functions without slippage protection
        swap_patterns = [r"swap\(", r"swapExact", r"exchange\("]
        swap_matches = _find_patterns(contract_code, swap_patterns)
        
        if swap_matches:
            # Check for minAmountOut or similar
            slippage_patterns = [r"minAmountOut", r"amountOutMin", r"minOut", r"slippage"]
            slippage_matches = _find_patterns(contract_code, slippage_patterns)
            
            if not slippage_matches:
                findings.append({
                    "type": "sandwich-vulnerable",
                    "severity": "HIGH",
                    "description": "Swap function detected without slippage protection - vulnerable to sandwich attacks",
                    "recommendation": "Add minAmountOut parameter and validate output amount",
                })
        
        # Check for deadline protection
        deadline_patterns = [r"deadline", r"expiry", r"validUntil"]
        deadline_matches = _find_patterns(contract_code, deadline_patterns)
        
        if swap_matches and not deadline_matches:
            findings.append({
                "type": "no-deadline",
                "severity": "MEDIUM",
                "description": "Time-sensitive operation without deadline - transactions can be held and executed later",
                "recommendation": "Add deadline parameter: require(block.timestamp <= deadline)",
            })
        
        # Check for front-runnable patterns
        frontrun_patterns = [
            {
                "pattern": r"commit.*reveal|reveal.*commit",
                "safe": True,
                "description": "Commit-reveal pattern detected (good)",
            },
            {
                "pattern": r"approve\([^)]+,\s*type\(uint256\)\.max",
                "safe": False,
                "type": "unlimited-approval",
                "severity": "MEDIUM",
                "description": "Unlimited token approval - can be exploited if contract is compromised",
            },
            {
                "pattern": r"transferOwnership",
                "safe": False,
                "type": "ownership-frontrun",
                "severity": "LOW",
                "description": "Ownership transfer can be front-run in some scenarios",
            },
        ]
        
        for pattern_info in frontrun_patterns:
            matches = _find_patterns(contract_code, [pattern_info["pattern"]])
            if matches and not pattern_info.get("safe", False):
                findings.append({
                    "type": pattern_info.get("type", "frontrun-risk"),
                    "severity": pattern_info.get("severity", "MEDIUM"),
                    "description": pattern_info["description"],
                    "matches": len(matches),
                })
        
        # Check for private mempool patterns
        private_patterns = [r"flashbots", r"private.*mempool", r"mev.*protect"]
        private_matches = _find_patterns(contract_code, private_patterns)
        
        mev_protection = "SOME" if private_matches else "NONE"
        
        return json.dumps({
            "mev_exposure": "HIGH" if any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings) else "MEDIUM" if findings else "LOW",
            "mev_protection_detected": mev_protection,
            "findings": findings,
            "total_findings": len(findings),
            "recommendations": [
                "Use private mempools (Flashbots Protect) for sensitive transactions",
                "Implement slippage protection on all swaps",
                "Add deadline parameters to time-sensitive operations",
                "Consider commit-reveal schemes for auction-like mechanisms",
            ] if findings else ["No major MEV vulnerabilities detected"],
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing MEV exposure: {str(e)}"})


@function_tool
def analyze_liquidation_risks(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze a lending protocol for liquidation-related vulnerabilities.
    
    Checks for:
    - Health factor manipulation
    - Liquidation incentive issues
    - Bad debt accumulation risks
    - Oracle dependency in liquidations
    
    Args:
        contract_code: Solidity source code to analyze
    
    Returns:
        JSON string with liquidation risk analysis
    """
    try:
        findings = []
        
        # Check for liquidation patterns
        liquidation_patterns = [r"liquidate", r"liquidation", r"healthFactor", r"collateralRatio"]
        liquidation_matches = _find_patterns(contract_code, liquidation_patterns)
        
        if not liquidation_matches:
            return json.dumps({
                "liquidation_detected": False,
                "message": "No liquidation patterns detected - may not be a lending protocol",
            }, indent=2)
        
        # Check for health factor validation
        health_patterns = [r"healthFactor\s*[><=]", r"isHealthy", r"isSolvent"]
        health_matches = _find_patterns(contract_code, health_patterns)
        
        if not health_matches:
            findings.append({
                "type": "missing-health-check",
                "severity": "CRITICAL",
                "description": "Liquidation logic without explicit health factor validation",
                "recommendation": "Add health factor check before allowing liquidation",
            })
        
        # Check for liquidation bonus/incentive
        bonus_patterns = [r"liquidationBonus", r"liquidationIncentive", r"liquidatorReward"]
        bonus_matches = _find_patterns(contract_code, bonus_patterns)
        
        if not bonus_matches:
            findings.append({
                "type": "no-liquidation-incentive",
                "severity": "MEDIUM",
                "description": "No liquidation incentive detected - liquidators may not be motivated",
                "recommendation": "Add liquidation bonus to incentivize timely liquidations",
            })
        
        # Check for bad debt handling
        bad_debt_patterns = [r"badDebt", r"shortfall", r"deficit", r"insuranceFund"]
        bad_debt_matches = _find_patterns(contract_code, bad_debt_patterns)
        
        if not bad_debt_matches:
            findings.append({
                "type": "no-bad-debt-handling",
                "severity": "HIGH",
                "description": "No bad debt handling mechanism detected",
                "recommendation": "Implement insurance fund or socialized loss mechanism",
            })
        
        # Check for partial liquidation support
        partial_patterns = [r"maxLiquidation", r"closeFactor", r"partialLiquidation"]
        partial_matches = _find_patterns(contract_code, partial_patterns)
        
        if not partial_matches:
            findings.append({
                "type": "no-partial-liquidation",
                "severity": "LOW",
                "description": "No partial liquidation support detected",
                "recommendation": "Consider implementing partial liquidations to reduce market impact",
            })
        
        return json.dumps({
            "liquidation_detected": True,
            "findings": findings,
            "total_findings": len(findings),
            "risk_level": "HIGH" if any(f["severity"] == "CRITICAL" for f in findings) else "MEDIUM" if findings else "LOW",
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing liquidation risks: {str(e)}"})


@function_tool
def analyze_governance_attacks(
    contract_code: str,
    ctf=None
) -> str:
    """
    Analyze a governance contract for attack vectors.
    
    Checks for:
    - Flash loan governance attacks
    - Timelock bypass opportunities
    - Quorum manipulation
    - Vote buying vulnerabilities
    
    Args:
        contract_code: Solidity source code to analyze
    
    Returns:
        JSON string with governance vulnerability analysis
    """
    try:
        findings = []
        
        # Check for governance patterns
        gov_patterns = [r"propose", r"vote", r"execute", r"Governor", r"governance"]
        gov_matches = _find_patterns(contract_code, gov_patterns)
        
        if not gov_matches:
            return json.dumps({
                "governance_detected": False,
                "message": "No governance patterns detected",
            }, indent=2)
        
        # Check for flash loan protection
        snapshot_patterns = [r"getPastVotes", r"getPriorVotes", r"snapshot", r"checkpoints"]
        snapshot_matches = _find_patterns(contract_code, snapshot_patterns)
        
        if not snapshot_matches:
            findings.append({
                "type": "flash-loan-governance",
                "severity": "CRITICAL",
                "description": "Governance without vote snapshots - vulnerable to flash loan attacks",
                "recommendation": "Use vote snapshots (getPastVotes) to prevent flash loan manipulation",
            })
        
        # Check for timelock
        timelock_patterns = [r"timelock", r"TimelockController", r"delay", r"eta"]
        timelock_matches = _find_patterns(contract_code, timelock_patterns)
        
        if not timelock_matches:
            findings.append({
                "type": "no-timelock",
                "severity": "HIGH",
                "description": "Governance without timelock - proposals execute immediately",
                "recommendation": "Add timelock delay for proposal execution",
            })
        
        # Check for quorum
        quorum_patterns = [r"quorum", r"minVotes", r"threshold"]
        quorum_matches = _find_patterns(contract_code, quorum_patterns)
        
        if not quorum_matches:
            findings.append({
                "type": "no-quorum",
                "severity": "HIGH",
                "description": "No quorum requirement detected - low participation attacks possible",
                "recommendation": "Implement minimum quorum for proposal validity",
            })
        
        # Check for vote delegation
        delegation_patterns = [r"delegate", r"delegateBySig", r"delegatee"]
        delegation_matches = _find_patterns(contract_code, delegation_patterns)
        
        if delegation_matches:
            # Check for delegation security
            sig_patterns = [r"nonces", r"DOMAIN_SEPARATOR", r"permit"]
            sig_matches = _find_patterns(contract_code, sig_patterns)
            
            if not sig_matches:
                findings.append({
                    "type": "delegation-replay",
                    "severity": "MEDIUM",
                    "description": "Vote delegation without replay protection",
                    "recommendation": "Implement nonces and domain separator for delegation signatures",
                })
        
        return json.dumps({
            "governance_detected": True,
            "has_snapshot_voting": len(snapshot_matches) > 0,
            "has_timelock": len(timelock_matches) > 0,
            "has_quorum": len(quorum_matches) > 0,
            "findings": findings,
            "total_findings": len(findings),
            "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM" if findings else "LOW",
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error analyzing governance attacks: {str(e)}"})


# Phase 3.1 Enhancements: Exact Numeric Simulation
# Enhancements include:
# - Flash loan size thresholds where attack becomes profitable
# - Slippage tolerance exploitation ranges
# - Liquidation profit margins
# - MEV simulation with actual TVL


@function_tool
def simulate_flash_loan_economics(
    contract_code: str,
    protocol_type: str = "vault",
    liquidity_pool_size: float = 1000000.0,
    ctf=None
) -> str:
    """
    Simulate flash loan attack economics with exact numeric thresholds.
    
    Use code interpreter to simulate:
    - Flash loan size thresholds where attack becomes profitable
    - Required capital / leverage
    - Net profit at different exploit scales
    - Minimum viable attack threshold
    
    Args:
        contract_code: Solidity source code
        protocol_type: Type of protocol (vault, lending, dex, governance)
        liquidity_pool_size: Estimated pool size in ETH
    
    Returns:
        JSON with economic simulation results
    """
    try:
        code_lower = contract_code.lower()
        
        # Flash loan fee structure
        FLASH_LOAN_FEES = {
            "aave": 0.0009,      # 0.09%
            "dydx": 0.0,           # 0%
            "uniswap_v3": 0.0003, # 0.03% but often 0
            "balancer": 0.0,          # 0%
            "maker": 0.0,            # 0%
        }
        
        # Detect flash loan providers
        flash_providers = []
        if "flashloan" in code_lower:
            flash_providers.append("generic")
        if "aave" in code_lower or "flashloan" in code_lower:
            flash_providers.append("aave")
        if "uniswap" in code_lower:
            flash_providers.append("uniswap_v3")
        if "balancer" in code_lower:
            flash_providers.append("balancer")
        
        # Extract protocol-specific parameters
        fee_rate = FLASH_LOAN_FEES.get(flash_providers[0], 0.0009)
        
        # Calculate minimum profitable flash loan size
        # Flash loan size must cover:
        # 1. Gas costs (~0.01-0.05 ETH)
        # 2. Flash loan fee (0-0.0009 * size)
        # 3. Potential slippage / impact
        # 4. Profit margin
        
        gas_cost_estimate = 0.02  # ~20-50 gwei * 50k gas
        min_profit_margin = 0.001  # 0.001 ETH minimum
        
        # Calculate thresholds for different scenarios
        scenarios = []
        
        # Scenario 1: Small pool (< 100 ETH)
        if liquidity_pool_size < 100.0:
            # Need higher profit margin per unit
            min_loan_size = (gas_cost_estimate + min_profit_margin) / (fee_rate + min_profit_margin)
            scenarios.append({
                "scenario": "small_pool",
                "pool_size_eth": liquidity_pool_size,
                "min_profitable_loan_size_eth": min_loan_size,
                "min_profitable_loan_size_usd": min_loan_size * 2000.0,  # $2000/ETH
                "flash_loan_fee_percent": fee_rate * 100,
                "gas_cost_estimate_eth": gas_cost_estimate,
                "min_profit_margin_eth": min_profit_margin,
            })
        
        # Scenario 2: Medium pool (100-1000 ETH)
        elif liquidity_pool_size < 1000.0:
            min_loan_size = (gas_cost_estimate + min_profit_margin) / (fee_rate + min_profit_margin)
            scenarios.append({
                "scenario": "medium_pool",
                "pool_size_eth": liquidity_pool_size,
                "min_profitable_loan_size_eth": min_loan_size,
                "min_profitable_loan_size_usd": min_loan_size * 2000.0,
                "flash_loan_fee_percent": fee_rate * 100,
                "gas_cost_estimate_eth": gas_cost_estimate,
                "min_profit_margin_eth": min_profit_margin,
            })
        
        # Scenario 3: Large pool (1000+ ETH)
        else:
            min_loan_size = (gas_cost_estimate + min_profit_margin) / (fee_rate + min_profit_margin)
            scenarios.append({
                "scenario": "large_pool",
                "pool_size_eth": liquidity_pool_size,
                "min_profitable_loan_size_eth": min_loan_size,
                "min_profitable_loan_size_usd": min_loan_size * 2000.0,
                "flash_loan_fee_percent": fee_rate * 100,
                "gas_cost_estimate_eth": gas_cost_estimate,
                "min_profit_margin_eth": min_profit_margin,
            })
        
        # Calculate maximum loan size (pool constraint)
        max_loan_size = liquidity_pool_size * 0.5  # Can't borrow more than 50% of pool
        
        results = {
            "flash_loan_providers_detected": flash_providers,
            "fee_rate": fee_rate,
            "liquidity_pool_size_eth": liquidity_pool_size,
            "max_loan_size_eth": max_loan_size,
            "scenarios": scenarios,
            "recommendations": [
                f"Flash loan attack only profitable if loan size > {scenarios[0]['min_profitable_loan_size_eth']:.4f} ETH (${scenarios[0]['min_profitable_loan_size_usd']:,.0f} USD)",
                f"Consider using 0-fee flash loan providers: {', '.join(['dYdX', 'Balancer']) if flash_providers else 'None'}",
                f"Gas costs vary significantly - recalculate with current gas prices",
            ],
        }
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error simulating flash loan economics: {str(e)}"})


@function_tool
def simulate_slippage_exploitation(
    contract_code: str,
    slippage_tolerance_percent: float = 0.3,
    tvl_usd: float = 1000000.0,
    ctf=None
) -> str:
    """
    Simulate slippage tolerance exploitation ranges.
    
    Calculate:
    - Maximum slippage that can be forced
    - Profit at different TVL levels
    - Minimum viable exploit threshold
    
    Args:
        contract_code: Solidity source code
        slippage_tolerance_percent: Current slippage tolerance (0.3% = 0.003)
        tvl_usd: Total Value Locked in protocol
    
    Returns:
        JSON with slippage exploitation analysis
    """
    try:
        code_lower = contract_code.lower()
        
        # Detect swap functions
        swap_patterns = [r"swap", r"exchange", r"trade", r"getAmountOut"]
        has_swaps = any(re.search(p, code_lower) for p in swap_patterns)
        
        if not has_swaps:
            return json.dumps({
                "swaps_detected": False,
                "message": "No swap functions detected in contract",
            }, indent=2)
        
        # Calculate max forced slippage
        max_slippage = slippage_tolerance_percent / 100.0  # Convert to decimal
        
        # Simulate profit at different slippage levels
        slippage_scenarios = []
        
        # Scenario 1: Low slippage (tolerance)
        profit_tolerance = 0.01  # 1% profit margin
        
        # At maximum slippage (tolerance): profit = 0 (no profit)
        # Above tolerance: forced slippage profit
        slippage_scenarios.append({
            "slippage_percent": max_slippage * 100,
            "description": "Maximum forced slippage (swap with no protection)",
            "profitable": True,
            "exploit_method": "sandwich_attack",
            "estimated_profit_pct": max_slippage - 0.01,
            "min_profit_threshold_eth": tvl_usd * 0.0001,  # 0.01% of TVL
        })
        
        # Calculate break-even slippage
        break_even_slippage = 0.01  # 1%
        
        slippage_scenarios.append({
            "slippage_percent": break_even_slippage * 100,
            "description": "Break-even slippage point",
            "profitable": True,
            "exploit_method": "slippage_manipulation",
            "estimated_profit_pct": 0.0,
            "min_profit_threshold_eth": tvl_usd * 0.0001,
        })
        
        # At tolerance: no profit for attacker
        slippage_scenarios.append({
            "slippage_percent": slippage_tolerance_percent,
            "description": "Within tolerance - no sandwich profit",
            "profitable": False,
            "exploit_method": "none",
            "estimated_profit_pct": 0.0,
            "min_profit_threshold_eth": tvl_usd * 0.0001,
        })
        
        # TVL-based profit scaling
        tvl_scaling_factors = {
            "small": 0.001,      # 0.001% of $100K TVL = $1 ETH
            "medium": 0.01,      # 0.01% of $100K TVL = $10 ETH
            "large": 0.1,        # 0.1% of $100K TVL = $100 ETH
        }
        
        results = {
            "swaps_detected": True,
            "current_tolerance_percent": slippage_tolerance_percent,
            "max_forced_slippage_percent": max_slippage * 100,
            "slippage_scenarios": slippage_scenarios,
            "tvl_usd": tvl_usd,
            "tvl_scaling_factors": tvl_scaling_factors,
            "recommendations": [
                f"Reduce slippage tolerance to <{break_even_slippage*100:.2f}% to prevent sandwich attacks",
                f"Implement minimum output protection (minAmountOut) with dynamic calculation",
                f"Use TWAP oracles to reduce forced slippage impact",
            ],
        }
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error simulating slippage exploitation: {str(e)}"})


@function_tool
def simulate_liquidation_profitability(
    contract_code: str,
    collateral_ratio_min: float = 1.15,
    liquidation_bonus_pct: float = 5.0,
    tvl_usd: float = 1000000.0,
    ctf=None
) -> str:
    """
    Simulate liquidation profit margins.
    
    Calculate:
    - Liquidation bonus/incentive structures
    - Minimum viable profit threshold
    - Collateralization ratio exploitation
    
    Args:
        contract_code: Solidity source code
        collateral_ratio_min: Minimum collateralization ratio (e.g., 115%)
        liquidation_bonus_pct: Liquidation bonus percentage
        tvl_usd: Total Value Locked
    
    Returns:
        JSON with liquidation profitability analysis
    """
    try:
        code_lower = contract_code.lower()
        
        # Detect liquidation patterns
        liquidation_patterns = [r"liquidate", r"healthFactor", r"collateral", r"seize"]
        has_liquidation = any(re.search(p, code_lower) for p in liquidation_patterns)
        
        if not has_liquidation:
            return json.dumps({
                "liquidation_detected": False,
                "message": "No liquidation patterns detected in contract",
            }, indent=2)
        
        # Calculate liquidation economics
        liquidation_bonus_decimal = liquidation_bonus_pct / 100.0
        
        # Scenario 1: Margin liquidation (close to ratio_min)
        margin_liquidation = {
            "scenario": "margin_liquidation",
            "collateral_ratio": collateral_ratio_min,
            "liquidation_bonus_pct": liquidation_bonus_pct,
            "bonus_value_usd": tvl_usd * (liquidation_bonus_decimal / 100.0),  # Bonus as % of TVL
            "attacker_profit_pct": liquidation_bonus_decimal,  # Attacker gets the bonus
            "min_profitable_position_usd": tvl_usd * 0.01,  # $10K position for $1M TVL
        }
        
        # Scenario 2: Under-collateralized (significantly below ratio_min)
        undercollateralized = {
            "scenario": "undercollateralized_position",
            "collateral_ratio": collateral_ratio_min * 0.85,  # 97.75%
            "liquidation_bonus_pct": liquidation_bonus_pct,
            "bonus_value_usd": tvl_usd * (liquidation_bonus_decimal / 100.0),
            "attacker_profit_pct": liquidation_bonus_decimal + (1.0 - 0.9775),  # Bonus + seized collateral
            "min_profitable_position_usd": tvl_usd * 0.005,  # $50K position
        }
        
        # Calculate minimum liquidation bonus for profitability
        min_bonus_for_profitability = (tvl_usd * 0.0005) / (liquidation_bonus_decimal / 100.0)  # 0.05% of TVL as min profit
        
        # Scenario 3: Zero or negative bonus (bad design)
        zero_bonus = {
            "scenario": "zero_bonus_liquidation",
            "collateral_ratio": collateral_ratio_min,
            "liquidation_bonus_pct": 0.0,
            "bonus_value_usd": 0.0,
            "attacker_profit_pct": 0.0,
            "min_profitable_position_usd": tvl_usd * 0.001,  # $1K position required for any profit
        }
        
        results = {
            "liquidation_detected": True,
            "collateral_ratio_min": collateral_ratio_min,
            "liquidation_bonus_pct": liquidation_bonus_pct,
            "scenarios": [margin_liquidation, undercollateralized, zero_bonus],
            "tvl_usd": tvl_usd,
            "min_bonus_threshold_usd": min_bonus_for_profitability,
            "recommendations": [
                "Ensure liquidation bonus > 0.01% of TVL to incentivize liquidators",
                "Implement proper health factor validation before liquidation",
                "Add close factor (maxLiquidation) to prevent full pool drain",
                "Consider partial liquidations to reduce market impact",
            ],
        }
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error simulating liquidation profitability: {str(e)}"})


@function_tool
def simulate_mev_sandwich(
    contract_code: str,
    tvl_usd: float = 1000000.0,
    block_gas_limit: int = 15000000,
    ctf=None
) -> str:
    """
    Simulate MEV sandwich attacks with actual TVL and gas parameters.
    
    Models:
    - Sandwich attack economics
    - Front-running opportunities
    - MEV extraction at different TVL scales
    
    Args:
        contract_code: Solidity source code
        tvl_usd: Total Value Locked
        block_gas_limit: Block gas limit (15M default)
    
    Returns:
        JSON with MEV simulation results
    """
    try:
        code_lower = contract_code.lower()
        
        # Detect swap functions
        swap_patterns = [r"swap", r"exchange"]
        has_swaps = any(re.search(p, code_lower) for p in swap_patterns)
        
        if not has_swaps:
            return json.dumps({
                "swaps_detected": False,
                "message": "No swap functions detected for MEV simulation",
            }, indent=2)
        
        # Sandwich attack economics
        # Front-run: attacker buys before victim
        # Back-run: attacker sells after victim's transaction moves price
        # Profit: price difference * victim_size
        
        # Calculate gas costs
        gas_price_gwei = 20  # ~$20 per 15M gas at 20 gwei
        tx_cost_usd = gas_price_gwei * block_gas_limit / 1e18 * 2000  # ETH price
        
        # MEV opportunity scaling with TVL
        mev_opportunity_pct = {
            "small_tvl": 0.1,    # 0.1% of $100K = $100
            "medium_tvl": 0.5,   # 0.5% of $100K = $500
            "large_tvl": 2.0,    # 2.0% of $100K = $2000
        }
        
        # Sandwich attack profit
        sandwich_scenarios = []
        
        # Small TVL scenario
        max_profit_pct = mev_opportunity_pct["small_tvl"]
        sandwich_scenarios.append({
            "scenario": "small_tvl_sandwich",
            "tvl_usd": tvl_usd,
            "mev_opportunity_pct": max_profit_pct,
            "max_profit_usd": tvl_usd * (max_profit_pct / 100.0),
            "tx_cost_usd": tx_cost_usd,
            "net_profit_usd": tvl_usd * (max_profit_pct / 100.0) - tx_cost_usd,
            "gas_price_gwei": gas_price_gwei,
            "block_gas_limit": block_gas_limit,
        })
        
        # Medium TVL scenario
        max_profit_pct = mev_opportunity_pct["medium_tvl"]
        sandwich_scenarios.append({
            "scenario": "medium_tvl_sandwich",
            "tvl_usd": tvl_usd,
            "mev_opportunity_pct": max_profit_pct,
            "max_profit_usd": tvl_usd * (max_profit_pct / 100.0),
            "tx_cost_usd": tx_cost_usd,
            "net_profit_usd": tvl_usd * (max_profit_pct / 100.0) - tx_cost_usd,
            "gas_price_gwei": gas_price_gwei,
            "block_gas_limit": block_gas_limit,
        })
        
        # Large TVL scenario
        max_profit_pct = mev_opportunity_pct["large_tvl"]
        sandwich_scenarios.append({
            "scenario": "large_tvl_sandwich",
            "tvl_usd": tvl_usd,
            "mev_opportunity_pct": max_profit_pct,
            "max_profit_usd": tvl_usd * (max_profit_pct / 100.0),
            "tx_cost_usd": tx_cost_usd,
            "net_profit_usd": tvl_usd * (max_profit_pct / 100.0) - tx_cost_usd,
            "gas_price_gwei": gas_price_gwei,
            "block_gas_limit": block_gas_limit,
        })
        
        results = {
            "swaps_detected": True,
            "tvl_usd": tvl_usd,
            "block_gas_limit": block_gas_limit,
            "gas_price_gwei": gas_price_gwei,
            "sandwich_scenarios": sandwich_scenarios,
            "recommendations": [
                "Use Flashbots or Flashbots Protect for private mempool submission",
                "Implement commit-reveal schemes for sensitive transactions",
                "Add slippage protection (minAmountOut) to limit sandwich profit",
                "Consider MEV protection services (MEV-Boost, bloXroute)",
                "Batch transactions to reduce MEV exposure",
            ],
        }
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Error simulating MEV sandwich attacks: {str(e)}"})
