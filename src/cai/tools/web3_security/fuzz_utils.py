"""
Fuzz-utils collection of fuzzing utilities for smart contracts.
Various utilities and helpers for smart contract fuzzing campaigns.
"""

from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import FUZZ_UTILS_BASE_PATH


@function_tool
def fuzz_utils_run(tool: str, args: str = "", ctf=None) -> str:
    """
    Run fuzz-utils tools for smart contract testing.

    Fuzz-utils provides various utilities for fuzzing, mutation testing,
    and test case generation for smart contracts.

    Args:
        tool: Specific fuzz-utils tool to run
        args: Arguments to pass to the tool
              Common tools and options:
              - seed-generator: Generate seed corpus for fuzzing
              - mutator: Mutate existing test cases
              - coverage-tracker: Track and analyze code coverage
              - corpus-minimizer: Minimize corpus while maintaining coverage

    Returns:
        str: Output from the fuzz-utils tool

    Examples:
        - Generate seeds: fuzz_utils_run("seed-generator", "--target contract.sol --output seeds/")
        - Minimize corpus: fuzz_utils_run("corpus-minimizer", "--input corpus/ --output min-corpus/")
    """
    command = f'{FUZZ_UTILS_BASE_PATH}/{tool} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def generate_fuzz_seeds(target: str, output_dir: str = "./seeds", args: str = "", ctf=None) -> str:
    """
    Generate seed inputs for fuzzing campaigns.

    Args:
        target: Path to contract or ABI file
        output_dir: Directory to save generated seeds
        args: Additional arguments for seed generation

    Returns:
        str: Seed generation results and file paths
    """
    command = f'{FUZZ_UTILS_BASE_PATH}/seed-generator --target {target} --output {output_dir} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def minimize_fuzz_corpus(input_dir: str, output_dir: str, args: str = "", ctf=None) -> str:
    """
    Minimize fuzzing corpus while maintaining code coverage.

    Args:
        input_dir: Directory containing original corpus
        output_dir: Directory for minimized corpus
        args: Additional arguments

    Returns:
        str: Corpus minimization results and statistics
    """
    command = f'{FUZZ_UTILS_BASE_PATH}/corpus-minimizer --input {input_dir} --output {output_dir} {args}'
    return run_command(command, ctf=ctf)


@function_tool
def analyze_fuzz_coverage(coverage_data: str, args: str = "", ctf=None) -> str:
    """
    Analyze code coverage from fuzzing campaigns.

    Args:
        coverage_data: Path to coverage data file or directory
        args: Additional analysis arguments

    Returns:
        str: Coverage analysis report
    """
    command = f'{FUZZ_UTILS_BASE_PATH}/coverage-tracker --data {coverage_data} {args}'
    return run_command(command, ctf=ctf)
