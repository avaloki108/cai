"""
Web3 Security Tools Package

This package contains integrations for various web3 security analysis tools
including static analyzers, fuzzers, and vulnerability scanners.

Available tools:
- Slither: Static analysis for Solidity
- Mythril: Symbolic execution and security analysis
- Securify: Formal verification and compliance checking
- Echidna: Property-based fuzzing
- Medusa: Coverage-guided fuzzing
- Fuzz-utils: Fuzzing utilities and helpers
"""

from .slither import slither_analyze, slither_check_upgradeability
from .mythril import mythril_analyze, mythril_disassemble, mythril_read_storage
from .securify import securify_analyze, securify_compliance_check
from .echidna import echidna_fuzz, echidna_assertion_mode, echidna_coverage
from .medusa import medusa_fuzz, medusa_init, medusa_test
from .fuzz_utils import (
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage
)

__all__ = [
    # Slither
    'slither_analyze',
    'slither_check_upgradeability',
    # Mythril
    'mythril_analyze',
    'mythril_disassemble',
    'mythril_read_storage',
    # Securify
    'securify_analyze',
    'securify_compliance_check',
    # Echidna
    'echidna_fuzz',
    'echidna_assertion_mode',
    'echidna_coverage',
    # Medusa
    'medusa_fuzz',
    'medusa_init',
    'medusa_test',
    # Fuzz Utils
    'fuzz_utils_run',
    'generate_fuzz_seeds',
    'minimize_fuzz_corpus',
    'analyze_fuzz_coverage',
]
