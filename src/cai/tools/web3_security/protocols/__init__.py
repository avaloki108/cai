"""
Protocol-Specific Analyzers for Web3 Security

This package provides specialized analyzers for different DeFi protocol types:
- Lending/Borrowing (Aave, Compound)
- AMM/DEX (Uniswap, Curve, Balancer)
- Governance (Governor, Timelock)
- Staking/Rewards
- ERC4626 Vaults
- Diamond Patterns
- L2/Rollup Security
- Options Protocols
- Yield Aggregators
"""

from cai.tools.web3_security.protocols.lending_analyzer import LendingAnalyzer, LendingVulnerability
from cai.tools.web3_security.protocols.amm_analyzer import AMMAnalyzer, AMMVulnerability
from cai.tools.web3_security.protocols.governance_analyzer import GovernanceAnalyzer, GovernanceVulnerability
from cai.tools.web3_security.protocols.staking_analyzer import StakingAnalyzer, StakingVulnerability
from cai.tools.web3_security.protocols.erc4626_analyzer import ERC4626Analyzer
from cai.tools.web3_security.protocols.diamond_analyzer import DiamondAnalyzer

# L2/Rollup Analyzer (for optimistic, ZK, validium rollups)
try:
    from cai.tools.web3_security.protocols.l2_analyzer import (
        detect_rollup_type,
        analyze_challenge_period,
        analyze_sequencer_risks,
        analyze_zk_verification,
        analyze_state_root_security,
        check_l2_bridge_patterns,
    )
    L2_AVAILABLE = True
except ImportError:
    L2_AVAILABLE = False

# Options Protocol Analyzer
try:
    from cai.tools.web3_security.protocols.options_analyzer import (
        analyze_option_mechanics,
        analyze_greeks_manipulation,
        analyze_settlement_security,
        analyze_liquidation_mechanics,
        analyze_premium_calculation,
        analyze_oracle_dependency,
    )
    OPTIONS_AVAILABLE = True
except ImportError:
    OPTIONS_AVAILABLE = False

# Yield Aggregator Analyzer
try:
    from cai.tools.web3_security.protocols.yield_aggregator_analyzer import (
        detect_harvest_vulnerabilities,
        detect_tvl_manipulation,
        detect_strategy_risks,
        detect_compound_vulnerabilities,
        detect_cross_strategy_risks,
        analyze_withdraw_patterns,
    )
    YIELD_AVAILABLE = True
except ImportError:
    YIELD_AVAILABLE = False


__all__ = [
    'LendingAnalyzer',
    'LendingVulnerability',
    'AMMAnalyzer',
    'AMMVulnerability',
    'GovernanceAnalyzer',
    'GovernanceVulnerability',
    'StakingAnalyzer',
    'StakingVulnerability',
    'ERC4626Analyzer',
    'DiamondAnalyzer',
]

# Add optional exports
if L2_AVAILABLE:
    __all__.extend([
        'detect_rollup_type',
        'analyze_challenge_period',
        'analyze_sequencer_risks',
        'analyze_zk_verification',
        'analyze_state_root_security',
        'check_l2_bridge_patterns',
    ])

if OPTIONS_AVAILABLE:
    __all__.extend([
        'analyze_option_mechanics',
        'analyze_greeks_manipulation',
        'analyze_settlement_security',
        'analyze_liquidation_mechanics',
        'analyze_premium_calculation',
        'analyze_oracle_dependency',
    ])

if YIELD_AVAILABLE:
    __all__.extend([
        'detect_harvest_vulnerabilities',
        'detect_tvl_manipulation',
        'detect_strategy_risks',
        'detect_compound_vulnerabilities',
        'detect_cross_strategy_risks',
        'analyze_withdraw_patterns',
    ])
