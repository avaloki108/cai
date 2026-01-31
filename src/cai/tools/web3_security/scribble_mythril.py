"""
Scribble + Mythril Integration for Property-Based Security Analysis.

This module combines Scribble's contract instrumentation with Mythril's symbolic
execution to verify custom properties and invariants in Solidity smart contracts.

Workflow:
1. Scribble instruments contracts with runtime assertions from annotations
2. Mythril symbolically executes the instrumented contract
3. Mythril detects assertion violations as property violations

Key Scribble annotation types:
- #if_succeeds: Postconditions (checked after function execution)
- #if_updated: State update conditions
- #invariant: Contract invariants (checked before/after state changes)
- #assert: Inline assertions
- #require: Preconditions

Example annotations:
    /// #if_succeeds {:msg "Balance must not underflow"} old(balances[msg.sender]) >= amount;
    function withdraw(uint256 amount) external { ... }

    /// #invariant {:msg "Total supply equals sum of balances"} totalSupply == sum(balances);

References:
- Scribble docs: https://docs.scribble.codes/
- Mythril user assertions: https://github.com/ConsenSys/mythril
"""

import os
import json
import tempfile
import shutil
from typing import Optional, Dict, Any, List
from cai.tools.common import run_command
from cai.sdk.agents import function_tool
from .config import SCRIBBLE_PATH, MYTHRIL_PATH


@function_tool
def scribble_instrument(
    target: str,
    output_mode: str = "flat",
    output_path: Optional[str] = None,
    user_assert_mode: str = "mstore",
    debug_events: bool = True,
    compiler_version: Optional[str] = None,
    path_remapping: Optional[str] = None,
    filter_type: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Instrument Solidity contracts with Scribble annotations for property-based testing.

    Scribble transforms property annotations (postconditions, invariants, assertions)
    into runtime checks that can be verified by Mythril or tested with fuzzers.

    Args:
        target: Path to Solidity file or directory containing contracts
        output_mode: Output mode - "flat" (single file), "files" (per-file), or "json"
        output_path: Output destination. For "flat"/"json": file path or "--" for stdout.
                    For "files": directory path (uses --utils-output-path for helpers)
        user_assert_mode: How to signal assertion failures to Mythril/Harvey.
                         "mstore" (recommended) or "log". Default: "mstore"
        debug_events: Emit debug events with variable values on failures. Default: True
        compiler_version: Specific Solidity compiler version (e.g., "0.8.17")
        path_remapping: Solc path remappings (semicolon-separated, e.g., "@oz/=node_modules/@openzeppelin/")
        filter_type: Regex to filter annotations by type (e.g., "invariant" only)
        extra_args: Additional Scribble CLI arguments

    Returns:
        str: Instrumentation result. For "flat" mode: instrumented source code.
             For "files" mode: list of generated files. For "json" mode: JSON artifact.

    Example annotations to add to your contracts:
        /// #if_succeeds {:msg "No underflow"} old(balances[msg.sender]) >= amount;
        /// #invariant {:msg "Supply conservation"} totalSupply == sum(balances);
        /// #assert {:msg "Valid state"} state != State.Invalid;
    """
    args = []

    # Output mode
    args.append(f"--output-mode {output_mode}")

    if output_path:
        if output_mode == "files":
            args.append(f"--utils-output-path {output_path}")
        else:
            args.append(f"--output {output_path}")

    # User assert mode for Mythril compatibility
    args.append(f"--user-assert-mode {user_assert_mode}")

    # Debug events for better error messages
    if debug_events:
        args.append("--debug-events")

    # Compiler settings
    if compiler_version:
        args.append(f"--compiler-version {compiler_version}")

    if path_remapping:
        args.append(f"--path-remapping {path_remapping}")

    # Filtering
    if filter_type:
        args.append(f"--filter-type {filter_type}")

    # Extra args
    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{SCRIBBLE_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def scribble_arm(
    target: str,
    output_dir: Optional[str] = None,
    compiler_version: Optional[str] = None,
    path_remapping: Optional[str] = None,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Arm Scribble instrumentation: swap instrumented files with originals in-place.

    This modifies files in-place, creating .original backups. Use scribble_disarm
    to restore originals after testing.

    Args:
        target: Path to Solidity file or directory
        output_dir: Directory for ReentrancyUtils.sol and other helpers
        compiler_version: Specific Solidity compiler version
        path_remapping: Solc path remappings
        extra_args: Additional Scribble CLI arguments

    Returns:
        str: List of armed files and their backup locations
    """
    args = ["--output-mode files", "--arm"]

    if output_dir:
        args.append(f"--utils-output-path {output_dir}")
    else:
        # Default to same directory as target
        target_dir = os.path.dirname(os.path.abspath(target)) or "."
        args.append(f"--utils-output-path {target_dir}")

    if compiler_version:
        args.append(f"--compiler-version {compiler_version}")

    if path_remapping:
        args.append(f"--path-remapping {path_remapping}")

    args.append("--user-assert-mode mstore")
    args.append("--debug-events")

    if extra_args:
        args.append(extra_args)

    args.append(target)

    command = f"{SCRIBBLE_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def scribble_disarm(
    target: str,
    keep_instrumented: bool = False,
    ctf=None
) -> str:
    """
    Disarm Scribble instrumentation: restore original contracts from backups.

    Finds all .original backup files and restores them, removing instrumented versions.

    Args:
        target: Path to Solidity file or directory to disarm
        keep_instrumented: If True, keep .instrumented files after restoring originals

    Returns:
        str: List of restored files
    """
    args = ["--disarm"]

    if keep_instrumented:
        args.append("--keep-instrumented")

    args.append(target)

    command = f"{SCRIBBLE_PATH} {' '.join(args)}"
    return run_command(command, ctf=ctf)


@function_tool
def scribble_mythril_verify(
    target: str,
    properties_file: Optional[str] = None,
    output_format: str = "text",
    execution_timeout: int = 300,
    max_depth: int = 128,
    strategy: str = "bfs",
    solver_timeout: int = 30000,
    compiler_version: Optional[str] = None,
    path_remapping: Optional[str] = None,
    mythril_args: str = "",
    scribble_args: str = "",
    cleanup: bool = True,
    ctf=None
) -> str:
    """
    Combined Scribble + Mythril workflow for property-based symbolic verification.

    This tool:
    1. Instruments contracts with Scribble (adds runtime checks from annotations)
    2. Runs Mythril symbolic execution on instrumented code
    3. Reports any property violations as security findings
    4. Optionally cleans up temporary files

    This is the recommended workflow for verifying custom invariants and postconditions
    using symbolic execution rather than fuzzing.

    Args:
        target: Path to Solidity file with Scribble annotations (/// #if_succeeds, etc.)
        properties_file: Optional separate file containing property definitions
        output_format: Mythril output format - "text", "json", "markdown", or "jsonv2"
        execution_timeout: Mythril execution timeout in seconds (default: 300)
        max_depth: Maximum symbolic execution depth (default: 128)
        strategy: Search strategy - "bfs" (breadth-first) or "dfs" (depth-first)
        solver_timeout: SMT solver timeout in milliseconds (default: 30000)
        compiler_version: Solidity compiler version (e.g., "0.8.17")
        path_remapping: Solc path remappings for imports
        mythril_args: Additional Mythril CLI arguments
        scribble_args: Additional Scribble CLI arguments
        cleanup: Remove temporary instrumented files after analysis (default: True)

    Returns:
        str: Combined analysis results including:
             - Scribble instrumentation summary
             - Mythril security analysis with property violations
             - Any assertion failures from instrumented checks

    Example usage:
        1. Add annotations to your contract:
           /// #if_succeeds {:msg "Balance conservation"} 
           ///     old(balanceOf(from)) + old(balanceOf(to)) == balanceOf(from) + balanceOf(to);
           function transfer(address to, uint256 amount) external returns (bool) { ... }

        2. Run verification:
           scribble_mythril_verify("Token.sol", compiler_version="0.8.17")

        3. Review violations - Mythril will report if any annotated property can be violated
    """
    results = []
    temp_dir = None
    instrumented_file = None

    try:
        # Create temp directory for instrumented output
        temp_dir = tempfile.mkdtemp(prefix="scribble_mythril_")
        base_name = os.path.basename(target)
        instrumented_file = os.path.join(temp_dir, f"instrumented_{base_name}")

        # Step 1: Instrument with Scribble
        results.append("=" * 60)
        results.append("STEP 1: Scribble Instrumentation")
        results.append("=" * 60)

        scribble_cmd_args = [
            f"--output-mode flat",
            f"--output {instrumented_file}",
            "--user-assert-mode mstore",
            "--debug-events",
        ]

        if compiler_version:
            scribble_cmd_args.append(f"--compiler-version {compiler_version}")

        if path_remapping:
            scribble_cmd_args.append(f"--path-remapping {path_remapping}")

        if scribble_args:
            scribble_cmd_args.append(scribble_args)

        # Handle properties file
        if properties_file:
            scribble_cmd_args.append(f"--macro-path {properties_file}")

        scribble_cmd_args.append(target)

        scribble_command = f"{SCRIBBLE_PATH} {' '.join(scribble_cmd_args)}"
        scribble_result = run_command(scribble_command, ctf=ctf)
        results.append(f"Command: {scribble_command}")
        results.append(f"Result: {scribble_result}")

        # Check if instrumentation succeeded
        if not os.path.exists(instrumented_file):
            results.append(f"\nERROR: Instrumentation failed - no output file created")
            results.append("Check that your contract has valid Scribble annotations.")
            return "\n".join(results)

        # Show instrumentation info
        with open(instrumented_file, 'r') as f:
            instrumented_content = f.read()
        
        # Count instrumented checks
        assertion_count = instrumented_content.count("__ScribbleUtilsLib")
        results.append(f"\nInstrumented file: {instrumented_file}")
        results.append(f"Instrumented checks added: ~{assertion_count}")

        # Step 2: Run Mythril on instrumented contract
        results.append("\n" + "=" * 60)
        results.append("STEP 2: Mythril Symbolic Execution")
        results.append("=" * 60)

        mythril_cmd_args = [
            f"-o {output_format}",
            f"--execution-timeout {execution_timeout}",
            f"--max-depth {max_depth}",
            f"--strategy {strategy}",
            f"--solver-timeout {solver_timeout}",
        ]

        if compiler_version:
            mythril_cmd_args.append(f"--solv {compiler_version}")

        if mythril_args:
            mythril_cmd_args.append(mythril_args)

        mythril_cmd_args.append(instrumented_file)

        mythril_command = f"{MYTHRIL_PATH} analyze {' '.join(mythril_cmd_args)}"
        results.append(f"Command: {mythril_command}")
        
        mythril_result = run_command(mythril_command, ctf=ctf)
        results.append(f"\n{mythril_result}")

        # Step 3: Parse and summarize findings
        results.append("\n" + "=" * 60)
        results.append("ANALYSIS SUMMARY")
        results.append("=" * 60)

        # Check for assertion violations (property violations from Scribble)
        if "Assertion Violation" in mythril_result or "assert" in mythril_result.lower():
            results.append("\n⚠️  PROPERTY VIOLATIONS DETECTED!")
            results.append("The symbolic execution found inputs that violate annotated properties.")
            results.append("Review the Mythril output above for specific violation details.")
        elif "The analysis was completed successfully" in mythril_result:
            results.append("\n✓ No property violations found within the analysis bounds.")
            results.append(f"  (execution_timeout={execution_timeout}s, max_depth={max_depth})")
        else:
            results.append("\nReview the Mythril output above for detailed findings.")

    except Exception as e:
        results.append(f"\nERROR during analysis: {str(e)}")

    finally:
        # Cleanup
        if cleanup and temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                results.append(f"\nCleaned up temporary files in {temp_dir}")
            except Exception as e:
                results.append(f"\nWarning: Could not cleanup temp dir: {e}")

    return "\n".join(results)


@function_tool
def scribble_coverage_check(
    target: str,
    compiler_version: Optional[str] = None,
    path_remapping: Optional[str] = None,
    mythril_timeout: int = 120,
    extra_args: str = "",
    ctf=None
) -> str:
    """
    Check which Scribble properties are reachable using Mythril coverage analysis.

    This instruments the contract with coverage assertions (--cov-assertions) and
    runs Mythril to determine which properties can actually be reached during
    execution. Useful for identifying dead code or unreachable invariants.

    Args:
        target: Path to Solidity file with Scribble annotations
        compiler_version: Solidity compiler version
        path_remapping: Solc path remappings
        mythril_timeout: Mythril execution timeout in seconds
        extra_args: Additional Scribble CLI arguments

    Returns:
        str: Coverage analysis showing which properties are reachable
    """
    results = []
    temp_dir = None

    try:
        temp_dir = tempfile.mkdtemp(prefix="scribble_cov_")
        base_name = os.path.basename(target)
        instrumented_file = os.path.join(temp_dir, f"cov_{base_name}")

        # Instrument with coverage assertions
        scribble_args = [
            "--output-mode flat",
            f"--output {instrumented_file}",
            "--user-assert-mode mstore",
            "--cov-assertions",  # Add coverage checking assertions
        ]

        if compiler_version:
            scribble_args.append(f"--compiler-version {compiler_version}")
        if path_remapping:
            scribble_args.append(f"--path-remapping {path_remapping}")
        if extra_args:
            scribble_args.append(extra_args)

        scribble_args.append(target)

        scribble_cmd = f"{SCRIBBLE_PATH} {' '.join(scribble_args)}"
        results.append("Instrumenting with coverage assertions...")
        scribble_result = run_command(scribble_cmd, ctf=ctf)
        results.append(scribble_result)

        if not os.path.exists(instrumented_file):
            return "Instrumentation failed - check Scribble annotations"

        # Run Mythril for coverage
        mythril_cmd = f"{MYTHRIL_PATH} analyze --execution-timeout {mythril_timeout} {instrumented_file}"
        results.append("\nRunning coverage analysis with Mythril...")
        mythril_result = run_command(mythril_cmd, ctf=ctf)
        results.append(mythril_result)

        # Parse coverage results
        results.append("\n" + "=" * 40)
        results.append("PROPERTY COVERAGE SUMMARY")
        results.append("=" * 40)
        
        if "Assertion Violation" in mythril_result:
            results.append("✓ Some properties are reachable (assertions triggered)")
        else:
            results.append("⚠️ No assertions were triggered - properties may be unreachable")
            results.append("   Consider: dead code, impossible preconditions, or insufficient depth")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return "\n".join(results)


@function_tool
def generate_scribble_annotations(
    contract_path: str,
    annotation_type: str = "all",
    ctf=None
) -> str:
    """
    Generate suggested Scribble annotations for common vulnerability patterns.

    This helper analyzes a contract and suggests property annotations that can
    catch common vulnerabilities when verified with Mythril.

    Args:
        contract_path: Path to Solidity contract to analyze
        annotation_type: Type of annotations to suggest:
                        - "all": All annotation types
                        - "balance": Balance/accounting invariants
                        - "access": Access control postconditions
                        - "reentrancy": Reentrancy guards
                        - "overflow": Arithmetic safety

    Returns:
        str: Suggested Scribble annotations with explanations
    """
    suggestions = []
    suggestions.append("=" * 60)
    suggestions.append("SUGGESTED SCRIBBLE ANNOTATIONS")
    suggestions.append("=" * 60)
    suggestions.append("\nAdd these annotations above relevant functions in your contract:\n")

    if annotation_type in ["all", "balance"]:
        suggestions.append("## Balance/Accounting Invariants")
        suggestions.append("""
/// #invariant {:msg "Total supply conservation"} 
///     totalSupply == __verifier_sum_uint(balances);

/// #if_succeeds {:msg "Transfer preserves total"} 
///     old(balanceOf(from)) + old(balanceOf(to)) == balanceOf(from) + balanceOf(to);

/// #if_succeeds {:msg "No balance underflow"} 
///     old(balanceOf(msg.sender)) >= amount;

/// #if_succeeds {:msg "Recipient balance increased"} 
///     balanceOf(to) == old(balanceOf(to)) + amount;
""")

    if annotation_type in ["all", "access"]:
        suggestions.append("\n## Access Control Postconditions")
        suggestions.append("""
/// #if_succeeds {:msg "Only owner can call"} 
///     old(msg.sender) == owner;

/// #if_succeeds {:msg "Admin role required"} 
///     old(hasRole(ADMIN_ROLE, msg.sender));

/// #if_succeeds {:msg "Not paused"} 
///     !old(paused);
""")

    if annotation_type in ["all", "reentrancy"]:
        suggestions.append("\n## Reentrancy Guards")
        suggestions.append("""
/// #if_succeeds {:msg "No reentrancy"} 
///     !__scribble_check_state_variable_reentrancy();

/// #if_succeeds {:msg "State updated before external call"} 
///     balances[msg.sender] == old(balances[msg.sender]) - amount;
""")

    if annotation_type in ["all", "overflow"]:
        suggestions.append("\n## Arithmetic Safety")
        suggestions.append("""
/// #if_succeeds {:msg "No overflow on add"} 
///     result >= a && result >= b;

/// #if_succeeds {:msg "No underflow on sub"} 
///     a >= b;

/// #if_succeeds {:msg "Multiplication no overflow"} 
///     b == 0 || result / b == a;
""")

    suggestions.append("\n" + "=" * 60)
    suggestions.append("USAGE")
    suggestions.append("=" * 60)
    suggestions.append("""
1. Add annotations above your contract functions
2. Run: scribble_mythril_verify("YourContract.sol")
3. Review any property violations reported by Mythril

For full Scribble syntax, see: https://docs.scribble.codes/
""")

    return "\n".join(suggestions)
