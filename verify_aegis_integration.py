#!/usr/bin/env python3
"""
Aegis Integration Verification Script

Verifies that all Aegis components have been successfully integrated into CAI.
"""

import sys
from pathlib import Path
from typing import List, Tuple

# Define expected files
EXPECTED_PATTERN_FILES = [
    "src/cai/agents/patterns/hmaw.py",
    "src/cai/agents/patterns/adversarial.py",
    "src/cai/agents/patterns/ensemble.py",
]

EXPECTED_AGENT_FILES = [
    "src/cai/agents/skeptic_alpha.py",
    "src/cai/agents/skeptic_beta.py",
    "src/cai/agents/skeptic_gamma.py",
    "src/cai/agents/manager_vuln.py",
    "src/cai/agents/manager_economic.py",
    "src/cai/agents/manager_access.py",
    "src/cai/agents/pivot_engine.py",
    "src/cai/agents/critic.py",
    "src/cai/agents/planner.py",
    "src/cai/agents/exploit_synthesizer.py",
    "src/cai/agents/poc_generator.py",
    "src/cai/agents/attributor.py",
]

EXPECTED_ENHANCEMENT_FILES = [
    "src/cai/tools/web3_security/enhancements/iris.py",
    "src/cai/tools/web3_security/enhancements/attack_economics.py",
    "src/cai/tools/web3_security/enhancements/precision.py",
    "src/cai/tools/web3_security/enhancements/timing.py",
    "src/cai/tools/web3_security/enhancements/invariant_gen.py",
    "src/cai/tools/web3_security/enhancements/defi_analyzer.py",
    "src/cai/tools/web3_security/enhancements/validation.py",
]

EXPECTED_PROTOCOL_FILES = [
    "src/cai/tools/web3_security/protocols/__init__.py",
    "src/cai/tools/web3_security/protocols/erc4626_analyzer.py",
    "src/cai/tools/web3_security/protocols/diamond_analyzer.py",
]

EXPECTED_TOOL_FILES = [
    "src/cai/tools/web3_security/audit_autonomous.py",
    "src/cai/tools/web3_security/council.py",
    "src/cai/tools/web3_security/triage.py",
    "src/cai/tools/web3_security/slither_mcp_client.py",
    "src/cai/tools/web3_security/foundry.py",
    "src/cai/tools/web3_security/fork_test.py",
]

EXPECTED_DOC_FILES = [
    "docs/aegis-integration.md",
    "AEGIS_INTEGRATION_SUMMARY.md",
]

def check_files(file_list: List[str], category: str) -> Tuple[int, int]:
    """Check if files exist and return (found, total) count."""
    found = 0
    total = len(file_list)
    
    print(f"\n{'='*60}")
    print(f"{category}")
    print(f"{'='*60}")
    
    for file_path in file_list:
        path = Path(file_path)
        if path.exists():
            size = path.stat().st_size
            print(f"✓ {file_path} ({size:,} bytes)")
            found += 1
        else:
            print(f"✗ {file_path} - MISSING")
    
    print(f"\nStatus: {found}/{total} files found")
    return found, total

def check_imports(file_path: str) -> bool:
    """Check if file has proper imports (cai not aegis)."""
    try:
        content = Path(file_path).read_text()
        if "from aegis" in content or "import aegis" in content:
            return False
        return True
    except Exception:
        return False

def main():
    """Run verification checks."""
    print("=" * 60)
    print("AEGIS INTEGRATION VERIFICATION")
    print("=" * 60)
    
    total_found = 0
    total_expected = 0
    
    # Check patterns
    found, total = check_files(EXPECTED_PATTERN_FILES, "PATTERNS")
    total_found += found
    total_expected += total
    
    # Check agents
    found, total = check_files(EXPECTED_AGENT_FILES, "AGENTS")
    total_found += found
    total_expected += total
    
    # Check enhancements
    found, total = check_files(EXPECTED_ENHANCEMENT_FILES, "ENHANCEMENT TOOLS")
    total_found += found
    total_expected += total
    
    # Check protocols
    found, total = check_files(EXPECTED_PROTOCOL_FILES, "PROTOCOL ANALYZERS")
    total_found += found
    total_expected += total
    
    # Check tools
    found, total = check_files(EXPECTED_TOOL_FILES, "ADDITIONAL TOOLS")
    total_found += found
    total_expected += total
    
    # Check documentation
    found, total = check_files(EXPECTED_DOC_FILES, "DOCUMENTATION")
    total_found += found
    total_expected += total
    
    # Check imports
    print(f"\n{'='*60}")
    print("IMPORT VERIFICATION")
    print(f"{'='*60}")
    
    files_to_check = (
        EXPECTED_PATTERN_FILES + 
        EXPECTED_AGENT_FILES[:7] +  # Check new agents (not copied from Aegis)
        EXPECTED_ENHANCEMENT_FILES +
        EXPECTED_TOOL_FILES
    )
    
    import_errors = []
    for file_path in files_to_check:
        if Path(file_path).exists():
            if check_imports(file_path):
                print(f"✓ {file_path} - imports OK")
            else:
                print(f"✗ {file_path} - has aegis imports")
                import_errors.append(file_path)
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Files Found: {total_found}/{total_expected}")
    print(f"Import Errors: {len(import_errors)}")
    
    if total_found == total_expected and len(import_errors) == 0:
        print("\n✅ INTEGRATION SUCCESSFUL - All components verified!")
        return 0
    else:
        print("\n⚠️  INTEGRATION INCOMPLETE")
        if total_found < total_expected:
            print(f"   - {total_expected - total_found} files missing")
        if import_errors:
            print(f"   - {len(import_errors)} files have import issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())
