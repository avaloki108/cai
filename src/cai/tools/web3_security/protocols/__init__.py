"""
Protocol-Specific Analyzers for Web3 Security

This package provides specialized analyzers for different DeFi protocol types:
- Lending/Borrowing (Aave, Compound)
- AMM/DEX (Uniswap, Curve, Balancer)
- Governance (Governor, Timelock)
- Staking/Rewards
- ERC4626 Vaults
- Diamond Patterns
"""

from cai.tools.web3_security.protocols.lending_analyzer import LendingAnalyzer, LendingVulnerability
from cai.tools.web3_security.protocols.amm_analyzer import AMMAnalyzer, AMMVulnerability
from cai.tools.web3_security.protocols.governance_analyzer import GovernanceAnalyzer, GovernanceVulnerability
from cai.tools.web3_security.protocols.staking_analyzer import StakingAnalyzer, StakingVulnerability
from cai.tools.web3_security.protocols.erc4626_analyzer import ERC4626Analyzer
from cai.tools.web3_security.protocols.diamond_analyzer import DiamondAnalyzer


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
