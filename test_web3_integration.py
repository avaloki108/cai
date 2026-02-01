#!/usr/bin/env python3
"""
Test script to verify web3 security tools integration.
This script checks that all tools are properly importable and configured.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all web3 security tools can be imported."""
    print("Testing web3 security tools imports...")

    try:
        from cai.tools.web3_security import (
            slither_analyze,
            slither_check_upgradeability,
            mythril_analyze,
            mythril_disassemble,
            mythril_read_storage,
            securify_analyze,
            securify_compliance_check,
            echidna_fuzz,
            echidna_assertion_mode,
            echidna_coverage,
            medusa_fuzz,
            medusa_init,
            medusa_test,
            fuzz_utils_run,
            generate_fuzz_seeds,
            minimize_fuzz_corpus,
            analyze_fuzz_coverage,
        )
        print("✓ All web3 security tools imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_agent_integration():
    """Test that bug bounty agent can access web3 tools."""
    print("\nTesting bug bounty agent integration...")

    try:
        from cai.agents.bug_bounter import bug_bounter_agent

        # Check that tools are in the agent's tool list
        tool_names = [tool.name for tool in bug_bounter_agent.tools]

        web3_tools = [
            'slither_analyze',
            'mythril_analyze',
            'securify_analyze',
            'echidna_fuzz',
            'medusa_fuzz',
        ]

        missing_tools = [tool for tool in web3_tools if tool not in tool_names]

        if missing_tools:
            print(f"✗ Missing tools in agent: {missing_tools}")
            return False

        print(f"✓ Bug bounty agent has {len([t for t in tool_names if any(w in t for w in ['slither', 'mythril', 'securify', 'echidna', 'medusa', 'fuzz'])])} web3 security tools")
        print("\nAvailable web3 tools in agent:")
        for tool_name in sorted(tool_names):
            if any(keyword in tool_name for keyword in ['slither', 'mythril', 'securify', 'echidna', 'medusa', 'fuzz']):
                print(f"  - {tool_name}")

        return True
    except Exception as e:
        print(f"✗ Agent integration error: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_tool_paths():
    """Check if tool executables exist at expected paths."""
    print("\nChecking tool installation paths...")

    tools = {
        'Slither': '/home/dok/tools/slither/slither',
        'Mythril': '/home/dok/tools/w3-audit/mythril2.0/myth2',
        'Securify': '/home/dok/tools/securify2.5/securify',
        'Echidna': '/home/dok/tools/w3-audit/echidna/echidna-2.2.7-x86_64-linux/echidna',
        'Medusa': '/home/dok/tools/w3-audit/medusa',
        'Fuzz-utils': '/home/dok/tools/w3-audit/fuzz-utils',
    }

    all_found = True
    for name, path in tools.items():
        if os.path.exists(path):
            print(f"✓ {name}: {path}")
        else:
            print(f"✗ {name}: NOT FOUND at {path}")
            all_found = False

    return all_found

def main():
    """Run all tests."""
    print("=" * 60)
    print("Web3 Security Tools Integration Test")
    print("=" * 60)

    results = []

    # Test imports
    results.append(("Imports", test_imports()))

    # Test agent integration
    results.append(("Agent Integration", test_agent_integration()))

    # Check tool paths
    results.append(("Tool Paths", check_tool_paths()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test_name}")

    all_passed = all(passed for _, passed in results)

    if all_passed:
        print("\n✓ All tests passed! Web3 security tools are properly integrated.")
        return 0
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

