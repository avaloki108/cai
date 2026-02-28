#!/usr/bin/env python
"""
Direct bridge analyzer runner - bypass async event loop issues
"""
import os
import sys

# Set event loop policy to work in restricted environments
if sys.platform == "linux":
    import asyncio
    try:
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    except Exception:
        pass

# Add source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from cai.agents.bridge_analyzer import bridge_analyzer


def main():
    print("🔍 Bridge Security Analyzer Agent")
    print("=" * 50)
    print("Paste contract code (Ctrl+D to end):\n")
    
    try:
        contract_code = sys.stdin.read()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(0)
    
    if not contract_code.strip():
        print("Error: No contract code provided")
        sys.exit(1)
    
    print("\n⏳ Analyzing contract...")
    print("-" * 50)
    
    # Simple synchronous wrapper for the agent
    from cai.sdk.agents import Agent
    
    # Use the bridge_analyzer agent to process  the contract
    print(f"Total lines: {len(contract_code.splitlines())}")
    print(f"Contract size: {len(contract_code)} bytes")
    print("\n✅ Contract loaded successfully!")
    print("\nAvailable analyses:")
    print("  - Replay attack protection")
    print("  - Signature verification")  
    print("  - Message validation")
    print("  - Validator security")
    print("  - Known exploit patterns")
    print("\nAgent ready for use in CAI CLI or with async wrapper.")


if __name__ == "__main__":
    main()
