import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    # Test importing all modules
    from web3_security_ai.base_agent import BaseAgent, AgentConfig, AgentType, AgentRole
    print('✓ Base agent imported successfully')
    
    from web3_security_ai.orchestrator import OrchestratorAgent
    print('✓ Orchestrator agent imported successfully')
    
    from web3_security_ai.web3_audit_agent import Web3AuditAgent
    print('✓ Web3 audit agent imported successfully')
    
    from web3_security_ai.ai_engine import AIEngine
    print('✓ AI engine imported successfully')
    
    from web3_security_ai.traditional_security_agent import TraditionalSecurityAgent
    print('✓ Traditional security agent imported successfully')
    
    from web3_security_ai.static_analysis_adapter import StaticAnalysisAdapter
    print('✓ Static analysis adapter imported successfully')
    
    from web3_security_ai.main import Web3SecurityAuditSystem
    print('✓ Main system imported successfully')
    
    # Test instantiation
    system = Web3SecurityAuditSystem()
    print('✓ System instantiated successfully')
    
    print('
All imports and instantiations successful!')
    
except Exception as e:
    print(f'✗ Error: {str(e)}')
    import traceback
    traceback.print_exc()
