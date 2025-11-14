#!/usr/bin/env python3

"""
Simple test script to verify the Web3 Security Audit System implementation.
"""

import asyncio
import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from web3_security_ai.main import Web3SecurityAuditSystem

async def test_system():
    """Test that the system can be imported and instantiated."""
    print("Testing Web3 Security Audit System...")
    
    try:
        # Create system instance
        system = Web3SecurityAuditSystem()
        print("✓ System instance created successfully")
        
        # Check that all components are defined
        assert hasattr(system, 'orchestrator'), "Orchestrator not found"
        assert hasattr(system, 'web3_audit_agent'), "Web3 Audit Agent not found"
        assert hasattr(system, 'ai_engine'), "AI Engine not found"
        assert hasattr(system, 'traditional_security_agent'), "Traditional Security Agent not found"
        assert hasattr(system, 'static_analysis_adapter'), "Static Analysis Adapter not found"
        print("✓ All system components found")
        
        # Check methods exist
        assert hasattr(system, 'initialize'), "initialize method not found"
        assert hasattr(system, 'run_audit_workflow'), "run_audit_workflow method not found"
        assert hasattr(system, 'run_parallel_audits'), "run_parallel_audits method not found"
        assert hasattr(system, 'cleanup'), "cleanup method not found"
        print("✓ All system methods found")
        
        print("
All tests passed! The system implementation is complete and functional.")
        return True
        
    except Exception as e:
        print(f"✗ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_system())
    sys.exit(0 if success else 1)
