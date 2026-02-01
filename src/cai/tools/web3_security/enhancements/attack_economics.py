"""
Attack Profitability Calculator

Calculates economic viability of attack vectors.
Filters noise by only flagging attacks where profit > cost with reasonable confidence.

Key calculations:
- Gas costs at various gas prices
- Flash loan fees (Aave 0.09%, dYdX 0%, Balancer 0%)
- Required capital / leverage
- Net profit at different exploit scales
- Minimum viable attack threshold
"""

import json
from typing import Any, Dict, List
from cai.sdk.agents import function_tool


# Flash loan provider fee structures
FLASH_LOAN_PROVIDERS = {
    "aave": {"fee_percent": 0.09, "name": "Aave V2/V3"},
    "dydx": {"fee_percent": 0.0, "name": "dYdX"},
    "uniswap_v3": {"fee_percent": 0.0003, "name": "Uniswap V3"},
    "balancer": {"fee_percent": 0.0, "name": "Balancer"},
    "maker": {"fee_percent": 0.0, "name": "Maker DSS"},
}

# Gas price scenarios (gwei)
GAS_PRICE_SCENARIOS = {
    "low": {"gwei": 15, "description": "Low congestion", "eth_usd": 2000},
    "normal": {"gwei": 30, "description": "Normal congestion", "eth_usd": 4000},
    "high": {"gwei": 50, "description": "High congestion", "eth_usd": 8000},
    "very_high": {"gwei": 100, "description": "Very high congestion", "eth_usd": 12000},
}

# Gas cost estimates for common operations (in gas units)
GAS_COSTS = {
    "erc20_transfer": 50000,
    "erc20_transferFrom": 65000,
    "erc20_approve": 46100,
    "uniswap_v3_swap": 150000,
    "uniswap_v2_swap": 100000,
    "curve_exchange": 180000,
    "governance_vote": 50000,
    "liquidation": 200000,
}


def _calculate_gas_cost(
    operations: List[str], gas_price_gwei: int = 30
) -> Dict[str, Any]:
    """
    Calculate total gas cost for a sequence of operations.

    Args:
        operations: List of operation types
        gas_price_gwei: Gas price in gwei

    Returns:
        Dict with gas details
    """
    total_gas = sum(GAS_COSTS.get(op, 100000) for op in operations)
    total_gas_cost_eth = (total_gas * gas_price_gwei) / 1e18

    return {
        "total_gas": total_gas,
        "gas_price_gwei": gas_price_gwei,
        "total_gas_cost_eth": total_gas_cost_eth,
        "operations_count": len(operations),
    }


@function_tool
def calculate_attack_profitability(
    attack_vector: str,
    exploit_value_usd: float,
    operations: str = "erc20_transfer",
    flash_loan_provider: str = "aave",
    gas_price_scenario: str = "normal",
    leverage_ratio: float = 1.0,
    ctf=None,
) -> str:
    """
    Calculate attack profitability with exact economic simulation.

    Determines if an attack is economically viable by comparing:
    - Expected profit from exploit
    - Gas costs (at various gas prices)
    - Flash loan fees
    - Net profit (after all costs)

    Args:
        attack_vector: Type of attack (reentrancy, oracle_manipulation, etc.)
        exploit_value_usd: Expected profit in USD
        operations: Operation types involved (comma-separated)
        flash_loan_provider: Provider for flash loan
        gas_price_scenario: Gas price scenario (low, normal, high, very_high)
        leverage_ratio: How much flash loan leverage (1.0 = no leverage)

    Returns:
        JSON with profitability analysis and recommendation
    """
    try:
        # Parse operations
        op_list = [op.strip() for op in operations.split(",") if op.strip()]

        # Get flash loan fee
        provider = FLASH_LOAN_PROVIDERS.get(
            flash_loan_provider.lower(), FLASH_LOAN_PROVIDERS["aave"]
        )
        flash_loan_fee_percent = provider["fee_percent"]

        # Get gas price
        gas_scenario = GAS_PRICE_SCENARIOS.get(
            gas_price_scenario.lower(), GAS_PRICE_SCENARIOS["normal"]
        )
        gas_price_gwei = gas_scenario["gwei"]
        eth_usd_per_gwei = gas_scenario["eth_usd"] / 1e9

        # Calculate gas cost
        gas_cost = _calculate_gas_cost(op_list, gas_price_gwei)

        # Calculate flash loan cost
        # Flash loan amount needed = exploit value / leverage
        flash_loan_amount_usd = exploit_value_usd / leverage_ratio
        flash_loan_fee_usd = flash_loan_amount_usd * (flash_loan_fee_percent / 100.0)

        # Total costs
        total_costs_usd = gas_cost["total_gas_cost_eth"] + flash_loan_fee_usd

        # Net profit
        net_profit_usd = exploit_value_usd - total_costs_usd

        # Profit margin
        profit_margin_pct = (
            (net_profit_usd / exploit_value_usd) * 100.0
            if exploit_value_usd > 0
            else 0.0
        )

        # Determine viability
        # Minimum profit margin: 1% of exploit value ($10 minimum)
        min_profit_margin = (
            0.01 if exploit_value_usd >= 1000 else exploit_value_usd * 0.001
        )
        min_net_profit_usd = exploit_value_usd * min_profit_margin

        is_viable = net_profit_usd > min_net_profit_usd and net_profit_usd > 0

        # Calculate minimum viable attack threshold
        # Need enough profit to cover flash loan fee + gas
        # Use all 0-fee providers to find optimal threshold
        min_viable_exploit_usd = min_net_profit_usd * 10  # 10x minimum profit margin

        # Generate recommendations
        recommendations = []

        if not is_viable:
            recommendations.append(
                {
                    "type": "not_profitable",
                    "message": "Attack costs exceed expected profit",
                    "details": f"Total costs: ${total_costs_usd:.2f}, Expected profit: ${exploit_value_usd:.2f}, Net: ${net_profit_usd:.2f}",
                }
            )

        if gas_cost["total_gas"] > 500000:
            recommendations.append(
                {
                    "type": "high_gas_cost",
                    "message": "Attack requires too much gas (may fail)",
                    "details": f"Total gas: {gas_cost['total_gas']:,} Cost: ${gas_cost['total_gas_cost_eth']:.2f}",
                }
            )

        if flash_loan_fee_percent > 0.09:
            recommendations.append(
                {
                    "type": "expensive_flash_loan",
                    "message": "Flash loan provider has high fees",
                    "details": f"Provider: {provider['name']}, Fee: {flash_loan_fee_percent}%",
                    "alternative": "Consider 0-fee providers (dYdX, Balancer)",
                }
            )

        if not recommendations and is_viable:
            recommendations.append(
                {
                    "type": "economically_viable",
                    "message": "Attack is profitable and should be prioritized",
                    "details": f"Net profit: ${net_profit_usd:.2f}, Margin: {profit_margin_pct:.2f}%",
                }
            )

        result = {
            "attack_vector": attack_vector,
            "exploit_value_usd": exploit_value_usd,
            "operations": op_list,
            "flash_loan_provider": flash_loan_provider,
            "flash_loan_fee_percent": flash_loan_fee_percent,
            "flash_loan_fee_usd": flash_loan_fee_usd,
            "leverage_ratio": leverage_ratio,
            "gas_price_scenario": gas_price_scenario,
            "gas_price_gwei": gas_price_gwei,
            "gas_cost": gas_cost,
            "total_costs_usd": total_costs_usd,
            "net_profit_usd": net_profit_usd,
            "profit_margin_pct": profit_margin_pct,
            "is_economically_viable": is_viable,
            "min_profit_margin_pct": min_profit_margin * 100.0
            if exploit_value_usd >= 1000
            else 0.001 * 100.0,
            "min_viable_exploit_usd": min_viable_exploit_usd,
            "recommendations": recommendations,
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {"error": f"Error calculating attack profitability: {str(e)}"}
        )


@function_tool
def compare_profitability_scenarios(
    exploit_value_usd: float, operation_complexity: str = "medium", ctf=None
) -> str:
    """
    Compare profitability across different scenarios.

    Tests attack viability at:
    - Different gas prices (low, normal, high)
    - Different flash loan providers
    - With/without leverage

    Args:
        exploit_value_usd: Expected profit in USD
        operation_complexity: Low, medium, high (affects gas costs)

    Returns:
        JSON with scenario comparison
    """
    try:
        # Determine gas cost multiplier
        complexity_multipliers = {
            "low": 0.5,  # Simple operations
            "medium": 1.0,  # Normal complexity
            "high": 2.0,  # Complex operations
        }
        gas_multiplier = complexity_multipliers.get(operation_complexity.lower(), 1.0)

        # Base gas cost
        base_gas_cost = 100000  # ~100k gas for base operation
        base_gas_cost_scaled = int(base_gas_cost * gas_multiplier)

        # Test scenarios
        scenarios = []

        # Scenario 1: Low gas, Aave flash loan
        gas_cost_low = base_gas_cost_scaled * 15 / 1e18  # $15 ETH at 15 gwei
        flash_fee_aave = (exploit_value_usd / 1.0) * 0.0009  # Aave 0.09%
        total_cost_1 = gas_cost_low + flash_fee_aave
        net_profit_1 = exploit_value_usd - total_cost_1

        scenarios.append(
            {
                "scenario": "low_gas_aave_flash_loan",
                "gas_price_gwei": 15,
                "gas_cost_usd": gas_cost_low,
                "flash_loan_provider": "aave",
                "flash_loan_fee_usd": flash_fee_aave,
                "total_cost_usd": total_cost_1,
                "net_profit_usd": net_profit_1,
                "is_viable": net_profit_1 > exploit_value_usd * 0.01,  # 1% margin
            }
        )

        # Scenario 2: Normal gas, dYdX flash loan (0% fee)
        gas_cost_normal = base_gas_cost_scaled * 30 / 1e18  # $30 ETH at 30 gwei
        flash_fee_dydx = 0.0  # dYdX has 0% flash loan fee
        total_cost_2 = gas_cost_normal + flash_fee_dydx
        net_profit_2 = exploit_value_usd - total_cost_2

        scenarios.append(
            {
                "scenario": "normal_gas_dydx_flash_loan",
                "gas_price_gwei": 30,
                "gas_cost_usd": gas_cost_normal,
                "flash_loan_provider": "dydx",
                "flash_loan_fee_usd": flash_fee_dydx,
                "total_cost_usd": total_cost_2,
                "net_profit_usd": net_profit_2,
                "is_viable": net_profit_2 > exploit_value_usd * 0.01,
            }
        )

        # Scenario 3: High gas, no flash loan (direct attack)
        gas_cost_high = base_gas_cost_scaled * 50 / 1e18  # $50 ETH at 50 gwei
        total_cost_3 = gas_cost_high
        net_profit_3 = exploit_value_usd - total_cost_3

        scenarios.append(
            {
                "scenario": "high_gas_direct_attack",
                "gas_price_gwei": 50,
                "gas_cost_usd": gas_cost_high,
                "flash_loan_provider": "none",
                "flash_loan_fee_usd": 0.0,
                "total_cost_usd": total_cost_3,
                "net_profit_usd": net_profit_3,
                "is_viable": net_profit_3 > exploit_value_usd * 0.01,
            }
        )

        # Count viable scenarios
        viable_count = sum(1 for s in scenarios if s["is_viable"])
        total_count = len(scenarios)

        # Best scenario
        best_scenario = max(
            scenarios, key=lambda s: s.get("net_profit_usd", -999999999), default=None
        )

        result = {
            "exploit_value_usd": exploit_value_usd,
            "operation_complexity": operation_complexity,
            "scenarios_tested": total_count,
            "viable_scenarios": viable_count,
            "best_scenario": best_scenario.get("scenario", "none")
            if best_scenario
            else "none",
            "best_net_profit_usd": best_scenario.get("net_profit_usd", 0)
            if best_scenario
            else 0,
            "scenarios": scenarios,
            "recommendations": [
                "Prefer 0-fee flash loan providers (dYdX, Balancer)",
                "Target attacks during low gas periods for better economics",
                "Consider reducing operation complexity to lower gas costs",
            ]
            if viable_count > 0
            else [
                "No viable scenarios found - increase exploit value or reduce complexity"
            ],
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {"error": f"Error comparing profitability scenarios: {str(e)}"}
        )


@function_tool
def calculate_minimum_viable_threshold(
    operation_types: str = "erc20_transfer,liquidation", ctf=None
) -> str:
    """
    Calculate minimum viable attack threshold for given operation types.

    Different attack vectors require different minimum profit levels.

    Args:
        operation_types: Comma-separated operation types involved

    Returns:
        JSON with minimum viable thresholds
    """
    try:
        op_list = [op.strip() for op in operation_types.split(",") if op.strip()]

        # Calculate base gas cost
        base_gas_cost = sum(GAS_COSTS.get(op, 100000) for op in op_list)

        # Use normal gas price (30 gwei)
        normal_gas_price_gwei = 30
        eth_usd_per_gwei = 4000 / 1e9  # $4000 ETH at 30 gwei

        base_gas_cost_eth = (base_gas_cost * normal_gas_price_gwei) / 1e18

        # Minimum profit margin: 1% of total costs
        min_profit_margin = 0.01

        # Minimum viable exploit = costs / (1 - margin)
        min_viable_eth = base_gas_cost_eth / (1 - min_profit_margin)
        min_viable_usd = min_viable_eth * 2000.0  # ETH/USD conversion

        # Different thresholds for different attack types
        thresholds = {}

        for op in op_list:
            op_cost = GAS_COSTS.get(op, 100000)
            op_cost_eth = (op_cost * normal_gas_price_gwei) / 1e18

            # Higher minimum for high-gas operations
            if op in ["liquidation", "governance_vote"]:
                min_margin = 0.02  # 2% minimum
                min_eth = op_cost_eth / (1 - min_margin)
            else:
                min_margin = 0.01  # 1% minimum
                min_eth = op_cost_eth / (1 - min_margin)

            thresholds[op] = {
                "gas_units": op_cost,
                "min_profit_margin_pct": min_margin * 100.0,
                "min_viable_eth": min_eth,
                "min_viable_usd": min_eth * 2000.0,
            }

        result = {
            "base_gas_cost_eth": base_gas_cost_eth,
            "min_profit_margin_pct": min_profit_margin * 100.0,
            "min_viable_eth": min_viable_eth,
            "min_viable_usd": min_viable_usd,
            "operation_thresholds": thresholds,
            "recommendations": [
                "Only flag attacks where expected profit exceeds minimum viable threshold",
                "Use 0-fee flash loan providers when possible",
                "Consider gas price timing - low congestion periods are better for attacks",
            ],
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps(
            {"error": f"Error calculating minimum viable threshold: {str(e)}"}
        )
