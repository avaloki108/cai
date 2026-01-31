"""
Certora Prover - Formal Verification for Smart Contracts

Certora Prover uses formal methods to mathematically prove contract properties,
detect complex vulnerabilities, and verify protocol invariants.
"""

from typing import Optional, List
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import CERTORA_PROVER_PATH


@function_tool
def certora_verify(
    files: str,
    verify: str,
    rule: Optional[str] = None,
    exclude_rule: Optional[str] = None,
    method: Optional[str] = None,
    exclude_method: Optional[str] = None,
    loop_iter: int = 1,
    optimistic_loop: bool = False,
    optimistic_hashing: bool = False,
    optimistic_fallback: bool = False,
    solc: Optional[str] = None,
    packages: Optional[str] = None,
    link: Optional[str] = None,
    msg: Optional[str] = None,
    rule_sanity: str = "basic",
    multi_assert_check: bool = False,
    wait_for_results: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Certora Prover formal verification on Solidity smart contracts.

    Certora mathematically proves properties defined in CVL specifications
    and detects complex vulnerabilities through formal methods.

    Args:
        files: Space-separated list of Solidity files to verify
        verify: Verification target in format "Contract:spec.spec"
        rule: Specific rule(s) to verify (supports wildcards *)
        exclude_rule: Rule(s) to exclude from verification
        method: Specific method(s) to verify
        exclude_method: Method(s) to exclude from verification
        loop_iter: Maximum loop iterations (default: 1)
        optimistic_loop: Assume loops terminate within loop_iter
        optimistic_hashing: Bound hash data length for performance
        optimistic_fallback: Ignore unresolved external calls
        solc: Path to Solidity compiler
        packages: Package path mappings (e.g., "@openzeppelin/=node_modules/@openzeppelin/")
        link: Link contracts (e.g., "Pool:asset=Asset")
        msg: Description message for the verification run
        rule_sanity: Sanity check level - "none", "basic", "advanced"
        multi_assert_check: Check each assertion separately
        wait_for_results: Wait for results ("all", "none", or timeout in seconds)
        extra_args: Additional Certora arguments

    Returns:
        str: Formal verification results with proved/disproved properties

    CVL Specification Example:
        ```cvl
        rule transferPreservesTotal {
            address from; address to; uint256 amount;
            uint256 totalBefore = balanceOf(from) + balanceOf(to);
            transfer(from, to, amount);
            uint256 totalAfter = balanceOf(from) + balanceOf(to);
            assert totalBefore == totalAfter;
        }
        ```

    Examples:
        certora_verify("Token.sol", "Token:Token.spec", rule="transferPreservesTotal")
        certora_verify("Pool.sol Asset.sol", "Pool:Pool.spec", link="Pool:asset=Asset")
    """
    args = [files, f"--verify {verify}"]

    if rule:
        args.append(f"--rule {rule}")

    if exclude_rule:
        args.append(f"--exclude_rule {exclude_rule}")

    if method:
        args.append(f"--method {method}")

    if exclude_method:
        args.append(f"--exclude_method {exclude_method}")

    args.append(f"--loop_iter {loop_iter}")

    if optimistic_loop:
        args.append("--optimistic_loop")

    if optimistic_hashing:
        args.append("--optimistic_hashing")

    if optimistic_fallback:
        args.append("--optimistic_fallback")

    if solc:
        args.append(f"--solc {solc}")

    if packages:
        args.append(f"--packages {packages}")

    if link:
        args.append(f"--link {link}")

    if msg:
        args.append(f'--msg "{msg}"')

    args.append(f"--rule_sanity {rule_sanity}")

    if multi_assert_check:
        args.append("--multi_assert_check")

    if wait_for_results:
        args.append(f"--wait_for_results {wait_for_results}")

    if extra_args:
        args.append(extra_args)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_foundry(
    project_dir: str = ".",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Verify all Foundry fuzz tests in the current project.

    Converts Foundry fuzz tests to formal verification problems and
    attempts to prove them using Certora.

    Args:
        project_dir: Path to Foundry project (default: current directory)
        extra_args: Additional arguments

    Returns:
        str: Verification results for all Foundry tests
    """
    args = ["--foundry"]

    if extra_args:
        args.append(extra_args)

    if project_dir != ".":
        args.append(project_dir)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_project_sanity(
    project_dir: str = ".",
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Perform basic sanity checks on all contracts in the project.

    Quick validation that contracts compile and have no obvious issues
    before running full verification.

    Args:
        project_dir: Path to project directory
        extra_args: Additional arguments

    Returns:
        str: Sanity check results
    """
    args = ["--project_sanity"]

    if extra_args:
        args.append(extra_args)

    if project_dir != ".":
        args.append(project_dir)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_compilation_only(
    files: str,
    verify: str,
    solc: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Compile spec and code without sending verification request.

    Useful for checking syntax and type errors in CVL specifications
    without waiting for full verification.

    Args:
        files: Space-separated list of Solidity files
        verify: Verification target "Contract:spec.spec"
        solc: Path to Solidity compiler
        extra_args: Additional arguments

    Returns:
        str: Compilation results and any syntax errors
    """
    args = [files, f"--verify {verify}", "--compilation_steps_only"]

    if solc:
        args.append(f"--solc {solc}")

    if extra_args:
        args.append(extra_args)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_with_linking(
    main_contract: str,
    spec: str,
    links: List[str],
    solc: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Verify with multiple contract linkings for complex protocols.

    Args:
        main_contract: Path to main contract file
        spec: Spec file to verify against
        links: List of link mappings (e.g., ["Pool:asset=Asset", "Pool:reward=Reward"])
        solc: Solidity compiler path
        extra_args: Additional arguments

    Returns:
        str: Verification results with linked contracts

    Example:
        certora_with_linking(
            "Pool.sol Asset.sol Reward.sol",
            "Pool:Pool.spec",
            ["Pool:asset=Asset", "Pool:reward=Reward"]
        )
    """
    args = [main_contract, f"--verify {spec}"]

    for link in links:
        args.append(f"--link {link}")

    if solc:
        args.append(f"--solc {solc}")

    if extra_args:
        args.append(extra_args)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_check_invariants(
    files: str,
    spec: str,
    contract: str,
    invariants: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Check contract invariants using Certora Prover.

    Invariants are properties that must hold before and after every
    public function call.

    Args:
        files: Space-separated list of Solidity files
        spec: Spec file containing invariant definitions
        contract: Contract name to verify
        invariants: Specific invariant(s) to check (comma-separated)
        extra_args: Additional arguments

    Returns:
        str: Invariant verification results

    CVL Invariant Example:
        ```cvl
        invariant totalSupplyIsSumOfBalances()
            totalSupply() == sum(balances)
        ```
    """
    verify = f"{contract}:{spec}"
    args = [files, f"--verify {verify}"]

    if invariants:
        args.append(f"--rule {invariants}")

    if extra_args:
        args.append(extra_args)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def certora_run_tests(
    files: str,
    spec: str,
    contract: str,
    satisfy_rules: Optional[str] = None,
    independent_satisfy: bool = True,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Run Certora tests using satisfy statements.

    Satisfy statements verify that certain states are reachable,
    useful for testing that code paths are not dead.

    Args:
        files: Space-separated list of Solidity files
        spec: Spec file containing satisfy tests
        contract: Contract name
        satisfy_rules: Specific satisfy rules to run
        independent_satisfy: Check each satisfy independently (default: True)
        extra_args: Additional arguments

    Returns:
        str: Test results showing reachable/unreachable states
    """
    verify = f"{contract}:{spec}"
    args = [files, f"--verify {verify}"]

    if satisfy_rules:
        args.append(f"--rule {satisfy_rules}")

    if independent_satisfy:
        args.append("--independent_satisfy")

    if extra_args:
        args.append(extra_args)

    command = f"{CERTORA_PROVER_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)
