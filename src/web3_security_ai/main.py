#!/usr/bin/env python3

"""
Main entry point for the merged Web3 Security Auditing AI System.
This module demonstrates the integration of all components.
"""

import asyncio
import json
from typing import Dict, List, Any
import logging
from datetime import datetime

from .base_agent import AgentConfig, AgentType, AgentRole
from .orchestrator import OrchestratorAgent
from .web3_audit_agent import Web3AuditAgent
from .ai_engine import AIEngine
from .traditional_security_agent import TraditionalSecurityAgent
from .static_analysis_adapter import StaticAnalysisAdapter, StaticAnalyzerType


class Web3SecurityAuditSystem:
    """Main system class that integrates all components of the security auditing system."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.orchestrator = None
        self.web3_audit_agent = None
        self.ai_engine = None
        self.traditional_security_agent = None
        self.static_analysis_adapter = None
        
        # Initialize the system
        self.initialized = False
    
    async def initialize(self):
        """Initialize all components of the system."""
        self.logger.info("Initializing Web3 Security Audit System...")
        
        # Create agent configurations
        orchestrator_config = AgentConfig(
            name="orchestrator_agent",
            agent_type=AgentType.ORCHESTRATOR,
            role=AgentRole.COORDINATOR,
            capabilities=["workflow_management", "task_coordination", "result_aggregation"]
        )
        
        web3_audit_config = AgentConfig(
            name="web3_audit_agent",
            agent_type=AgentType.WEB3_AUDIT,
            role=AgentRole.ANALYST,
            capabilities=["smart_contract_analysis", "vulnerability_detection", "confidence_scoring"]
        )
        
        ai_engine_config = AgentConfig(
            name="ai_ml_engine",
            agent_type=AgentType.AI_ML,
            role=AgentRole.EVALUATOR,
            capabilities=["smartbert_embeddings", "smartintentnn", "similarity_matching", "intent_detection"]
        )
        
        traditional_security_config = AgentConfig(
            name="traditional_security_agent",
            agent_type=AgentType.TRADITIONAL_SECURITY,
            role=AgentRole.ANALYST,
            capabilities=["reconnaissance", "vulnerability_scanning", "network_analysis"]
        )
        
        # Initialize agents
        self.orchestrator = OrchestratorAgent(orchestrator_config)
        self.web3_audit_agent = Web3AuditAgent(web3_audit_config)
        self.ai_engine = AIEngine(ai_engine_config)
        self.traditional_security_agent = TraditionalSecurityAgent(traditional_security_config)
        self.static_analysis_adapter = StaticAnalysisAdapter()
        
        # Initialize all agents
        await self.orchestrator.initialize()
        await self.web3_audit_agent.initialize()
        await self.ai_engine.initialize()
        await self.traditional_security_agent.initialize()
        
        # Register agents with orchestrator
        await self.orchestrator.register_agent(self.web3_audit_agent)
        await self.orchestrator.register_agent(self.ai_engine)
        await self.orchestrator.register_agent(self.traditional_security_agent)
        
        self.initialized = True
        self.logger.info("Web3 Security Audit System initialized successfully")
    
    async def run_audit_workflow(self, contract_source: str, contract_address: str = "0x0") -> Dict[str, Any]:
        """Run a complete audit workflow.
        
        Args:
            contract_source: Source code of the smart contract to audit
            contract_address: Address of the contract (optional)
            
        Returns:
            Dictionary with complete audit results
        """
        if not self.initialized:
            await self.initialize()
        
        self.logger.info(f"Starting audit workflow for contract: {contract_address}")
        
        # Start timing
        start_time = datetime.now()
        
        # 1. AI/ML Analysis
        self.logger.info("Running AI/ML analysis...")
        ai_embedding_result = await self.ai_engine.execute_task(json.dumps({
            "type": "embedding",
            "text": contract_source
        }))
        
        ai_intent_result = await self.ai_engine.execute_task(json.dumps({
            "type": "intent_classification",
            "text": contract_source
        }))
        
        # 2. Web3 Audit Analysis
        self.logger.info("Running Web3 audit analysis...")
        web3_audit_result = await self.web3_audit_agent.execute_task(json.dumps({
            "contract_address": contract_address,
            "contract_source": contract_source,
            "analysis_type": "full"
        }))
        
        # 3. Static Analysis
        self.logger.info("Running static analysis...")
        static_results = []
        for analyzer_type in [StaticAnalyzerType.SLITHER, StaticAnalyzerType.MYTHRIL, StaticAnalyzerType.SECURIFY2]:
            result = await self.static_analysis_adapter.run_analysis(
                contract_source, analyzer_type
            )
            static_results.append(result)
        
        combined_static_results = self.static_analysis_adapter.combine_results(static_results)
        
        # 4. Traditional Security Analysis
        self.logger.info("Running traditional security analysis...")
        traditional_result = await self.traditional_security_agent.execute_task(json.dumps({
            "tool_type": "vulnerability_scanning",
            "target": contract_address,
            "parameters": {}
        }))
        
        # 5. Combine all results and calculate final confidence
        final_confidence = self._calculate_final_confidence(
            ai_results=ai_intent_result.get("result", {}),
            web3_results=web3_audit_result.get("result", {}),
            static_results=combined_static_results,
            traditional_results=traditional_result.get("result", [])
        )
        
        # 6. Generate final report
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        final_report = {
            "contract_address": contract_address,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "ai_analysis": ai_intent_result.get("result", {}),
            "web3_audit": web3_audit_result.get("result", {}),
            "static_analysis": combined_static_results,
            "traditional_security": traditional_result.get("result", []),
            "final_confidence": final_confidence,
            "recommendations": self._generate_recommendations(
                ai_intent_result.get("result", {}),
                web3_audit_result.get("result", {}),
                combined_static_results
            ),
            "severity_summary": self._generate_severity_summary(
                web3_audit_result.get("result", {}),
                combined_static_results
            )
        }
        
        self.logger.info(f"Audit workflow completed for contract: {contract_address}")
        return final_report
    
    def _calculate_final_confidence(self, ai_results: Dict[str, Any], 
                                  web3_results: Dict[str, Any],
                                  static_results: Dict[str, Any],
                                  traditional_results: List[Dict[str, Any]]) -> float:
        """Calculate final confidence score using weighted formula.
        
        Args:
            ai_results: AI/ML analysis results
            web3_results: Web3 audit results
            static_results: Static analysis results
            traditional_results: Traditional security results
            
        Returns:
            Final confidence score (0-1)
        """
        # Extract confidence components
        ai_confidence = ai_results.get("confidence_scores", {}).get("malicious", 0.0)
        web3_confidence = web3_results.get("confidence_score", 0.0)
        static_confidence = static_results.get("average_confidence", 0.0)
        
        # Apply weighted formula: AI_Intent * 0.4 + Web3 * 0.3 + Static * 0.2 + Traditional * 0.1
        final_confidence = (
            ai_confidence * 0.4 +
            web3_confidence * 0.3 +
            static_confidence * 0.2 +
            len(traditional_results) * 0.01  # Simplified traditional contribution
        )
        
        return min(1.0, final_confidence)
    
    def _generate_recommendations(self, ai_results: Dict[str, Any], 
                                web3_results: Dict[str, Any],
                                static_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on all analysis results.
        
        Args:
            ai_results: AI/ML analysis results
            web3_results: Web3 audit results
            static_results: Static analysis results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # AI-based recommendations
        classification = ai_results.get("classification", "unknown")
        if classification == "malicious":
            recommendations.append("Critical: AI analysis detected potentially malicious intent. Review code carefully.")
        
        # Web3 audit recommendations
        vulnerabilities = web3_results.get("vulnerabilities", [])
        if vulnerabilities:
            recommendations.append(f"Web3 audit detected: {', '.join(vulnerabilities)}")
        
        # Static analysis recommendations
        findings_count = static_results.get("total_findings", 0)
        if findings_count > 0:
            recommendations.append(f"Static analysis found {findings_count} potential issues")
        
        return recommendations
    
    def _generate_severity_summary(self, web3_results: Dict[str, Any],
                                 static_results: Dict[str, Any]) -> Dict[str, int]:
        """Generate severity summary from all analysis results.
        
        Args:
            web3_results: Web3 audit results
            static_results: Static analysis results
            
        Returns:
            Dictionary mapping severity levels to counts
        """
        severity_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Add Web3 audit findings
        web3_findings = web3_results.get("findings", [])
        for finding in web3_findings:
            severity = finding.get("severity", "unknown").lower()
            if severity in severity_summary:
                severity_summary[severity] += 1
        
        # Add static analysis findings
        static_breakdown = static_results.get("severity_breakdown", {})
        for severity, count in static_breakdown.items():
            severity_lower = severity.lower()
            if severity_lower in severity_summary:
                severity_summary[severity_lower] += count
        
        return severity_summary
    
    async def run_parallel_audits(self, contracts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Run multiple audits in parallel.
        
        Args:
            contracts: List of contracts with source code and address
            
        Returns:
            List of audit results
        """
        if not self.initialized:
            await self.initialize()
        
        self.logger.info(f"Running parallel audits for {len(contracts)} contracts")
        
        # Run audits concurrently
        tasks = [
            self.run_audit_workflow(contract["source"], contract.get("address", "0x0"))
            for contract in contracts
        ]
        
        results = await asyncio.gather(*tasks)
        self.logger.info(f"Completed parallel audits for {len(contracts)} contracts")
        
        return results
    
    async def cleanup(self):
        """Clean up the system and all agents."""
        if self.orchestrator:
            await self.orchestrator.cleanup()
        if self.web3_audit_agent:
            await self.web3_audit_agent.cleanup()
        if self.ai_engine:
            await self.ai_engine.cleanup()
        if self.traditional_security_agent:
            await self.traditional_security_agent.cleanup()
        
        self.logger.info("Web3 Security Audit System cleaned up")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get status of the entire system.
        
        Returns:
            Dictionary with system status information
        """
        return {
            "initialized": self.initialized,
            "orchestrator_status": self.orchestrator.get_status() if self.orchestrator else None,
            "web3_audit_status": self.web3_audit_agent.get_status() if self.web3_audit_agent else None,
            "ai_engine_status": self.ai_engine.get_status() if self.ai_engine else None,
            "traditional_security_status": self.traditional_security_agent.get_status() if self.traditional_security_agent else None,
            "registered_agents": self.orchestrator.get_agent_summary() if self.orchestrator else {}
        }


# Example usage and demonstration
async def main():
    """Main function to demonstrate the system capabilities."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create system instance
    system = Web3SecurityAuditSystem()
    
    try:
        # Initialize the system
        await system.initialize()
        
        # Sample smart contract for testing
        sample_contract = """pragma solidity ^0.8.0;

contract SampleVulnerableContract {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        // Vulnerability: Direct transfer without reentrancy protection
        (bool success, ) = msg.sender.call{value: amount}();
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
    
    function transfer(address to, uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}"""
        
        # Run audit workflow
        print("Running Web3 Security Audit System...")
        result = await system.run_audit_workflow(
            contract_source=sample_contract,
            contract_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        )
        
        # Print results
        print(f"
Audit Results for Contract: {result['contract_address']}")
        print(f"Duration: {result['duration_seconds']:.2f} seconds")
        print(f"Final Confidence Score: {result['final_confidence']:.2f}")
        print(f"AI Intent Classification: {result['ai_analysis'].get('classification', 'N/A')}")
        print(f"Web3 Audit Findings: {len(result['web3_audit'].get('findings', []))} issues found")
        print(f"Static Analysis Findings: {result['static_analysis']['total_findings']} issues found")
        
        print(f"
Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
        
        print(f"
Severity Summary:")
        for severity, count in result['severity_summary'].items():
            if count > 0:
                print(f"  {severity.capitalize()}: {count}")
        
        # Clean up
        await system.cleanup()
        
    except Exception as e:
        print(f"Error running audit system: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
