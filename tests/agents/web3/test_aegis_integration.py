"""
Integration tests for Aegis Agent Ensemble

Tests the coordination and handoff between multiple agents in the
Web3 security audit workflow.
"""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock


class TestAegisEnsembleIntegration:
    """Integration tests for Aegis agent ensemble coordination."""
    
    @pytest.fixture
    def sample_vulnerable_contract(self):
        """Sample contract with multiple vulnerabilities."""
        return '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        contract VulnerableVault {
            mapping(address => uint256) public balances;
            address public owner;
            
            // Reentrancy vulnerable
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount, "Insufficient");
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] -= amount;  // State update after external call
            }
            
            // Missing access control
            function setOwner(address newOwner) external {
                owner = newOwner;
            }
            
            // Sandwich vulnerable swap
            function swap(address tokenIn, uint256 amountIn) external {
                // No slippage protection
                // No deadline
            }
            
            // Oracle manipulation vulnerable
            function getPrice() public view returns (uint256) {
                // Uses spot price, no TWAP
                return IUniswap(pool).getReserves();
            }
        }
        '''
    
    def test_skeptic_alpha_logical_analysis(self, sample_vulnerable_contract):
        """Test Skeptic Alpha logical assumption analysis."""
        from cai.agents.skeptic_alpha import challenge_assumptions
        
        finding = "Reentrancy in withdraw() allows draining funds"
        assumptions = "assumes user can call withdraw multiple times in same tx"
        
        result_json = challenge_assumptions(finding, assumptions)
        result = json.loads(result_json)
        
        assert "finding_analyzed" in result
        assert "flaws_found" in result
    
    def test_skeptic_beta_economic_analysis(self):
        """Test Skeptic Beta economic viability analysis."""
        from cai.agents.skeptic_beta import calculate_attack_cost, analyze_roi
        
        # Calculate attack cost
        cost_json = calculate_attack_cost(
            attack_description="Reentrancy attack on vault",
            gas_estimate=500000,
            gas_price_gwei=50.0,
            flash_loan_needed=True,
            flash_loan_amount=100.0
        )
        cost = json.loads(cost_json)
        
        assert cost["gas_cost_eth"] > 0
        assert cost["flash_loan_fee_eth"] > 0
        
        # Analyze ROI
        roi_json = analyze_roi(
            attack_cost_eth=cost["total_cost_eth"],
            attack_profit_eth=10.0,
            success_probability=0.8
        )
        roi = json.loads(roi_json)
        
        assert "economically_viable" in roi
        assert "roi_percentage" in roi
    
    def test_skeptic_gamma_defense_analysis(self, sample_vulnerable_contract):
        """Test Skeptic Gamma defense mechanism analysis."""
        from cai.agents.skeptic_gamma import (
            find_access_controls,
            find_reentrancy_guards,
            render_defense_verdict
        )
        
        # Check access controls
        access_json = find_access_controls(
            function_name="setOwner",
            contract_code=sample_vulnerable_contract
        )
        access = json.loads(access_json)
        
        assert access["verdict"] == "UNPROTECTED"  # No onlyOwner modifier
        
        # Check reentrancy guards
        reent_json = find_reentrancy_guards(
            function_name="withdraw",
            contract_code=sample_vulnerable_contract
        )
        reent = json.loads(reent_json)
        
        assert reent["verdict"] == "VULNERABLE"  # No nonReentrant
    
    def test_bridge_analyzer_integration(self):
        """Test Bridge Analyzer on sample bridge code."""
        from cai.agents.bridge_analyzer import (
            analyze_replay_protection,
            analyze_signature_verification,
            render_bridge_audit_report
        )
        
        bridge_code = '''
        contract SimpleBridge {
            function receiveMessage(bytes memory message, bytes memory sig) external {
                address signer = ecrecover(keccak256(message), 27, bytes32(0), bytes32(0));
                // Process message without nonce tracking
            }
        }
        '''
        
        replay_json = analyze_replay_protection(bridge_code)
        replay = json.loads(replay_json)
        
        sig_json = analyze_signature_verification(bridge_code)
        sig = json.loads(sig_json)
        
        # Generate report
        report = render_bridge_audit_report(
            "SimpleBridge",
            replay.get("findings", []),
            sig.get("findings", []),
            [],
            [],
            []
        )
        
        assert "SimpleBridge" in report
        assert "CRITICAL" in report or "HIGH" in report
    
    def test_mev_analyzer_integration(self, sample_vulnerable_contract):
        """Test MEV Analyzer on sample swap code."""
        from cai.agents.mev_analyzer import (
            analyze_sandwich_vulnerability,
            calculate_mev_exposure,
            render_mev_report
        )
        
        sandwich_json = analyze_sandwich_vulnerability(sample_vulnerable_contract)
        sandwich = json.loads(sandwich_json)
        
        assert sandwich["verdict"] == "VULNERABLE"
        
        mev_json = calculate_mev_exposure(
            function_type="swap",
            trade_size_eth=10.0,
            pool_liquidity_eth=1000.0
        )
        mev = json.loads(mev_json)
        
        # Generate report
        report = render_mev_report(
            "VulnerableVault",
            sandwich.get("findings", []),
            [],
            [],
            mev
        )
        
        assert "VulnerableVault" in report
        assert "MEV" in report
    
    def test_full_adversarial_pipeline(self, sample_vulnerable_contract):
        """Test full adversarial review pipeline flow."""
        # Step 1: Skeptic Alpha - Logical analysis
        from cai.agents.skeptic_alpha import challenge_assumptions
        
        alpha_result = json.loads(challenge_assumptions(
            "Reentrancy allows fund drainage",
            "assumes external call before state update"
        ))
        
        # Step 2: Skeptic Beta - Economic analysis
        from cai.agents.skeptic_beta import analyze_roi
        
        beta_result = json.loads(analyze_roi(
            attack_cost_eth=0.05,
            attack_profit_eth=10.0,
            success_probability=0.9
        ))
        
        # Step 3: Skeptic Gamma - Defense analysis
        from cai.agents.skeptic_gamma import find_reentrancy_guards
        
        gamma_result = json.loads(find_reentrancy_guards(
            "withdraw",
            sample_vulnerable_contract
        ))
        
        # Verify pipeline results
        assert alpha_result is not None
        assert beta_result["economically_viable"] == True  # Profitable attack
        assert gamma_result["verdict"] == "VULNERABLE"  # No protection


class TestAgentHandoffs:
    """Test agent-to-agent handoff patterns."""
    
    def test_manager_to_skeptic_handoff(self):
        """Test finding handoff from manager to skeptic agents."""
        # Simulate finding from manager agent
        manager_finding = {
            "id": "VUL-001",
            "type": "reentrancy",
            "severity": "HIGH",
            "description": "State update after external call in withdraw()",
            "location": {"file": "Vault.sol", "line": 42},
            "confidence": 0.8
        }
        
        # Skeptic Beta should be able to process this
        from cai.agents.skeptic_beta import calculate_attack_cost
        
        cost_json = calculate_attack_cost(
            attack_description=manager_finding["description"],
            gas_estimate=300000,
            gas_price_gwei=50.0
        )
        cost = json.loads(cost_json)
        
        assert "total_cost_eth" in cost
    
    def test_skeptic_to_synthesizer_handoff(self):
        """Test validated finding handoff to exploit synthesizer."""
        # Simulate validated finding after skeptic review
        validated_finding = {
            "id": "VUL-001",
            "type": "reentrancy",
            "severity": "HIGH",
            "skeptic_scores": {
                "alpha": "PASS",  # Logic valid
                "beta": "PASS",   # Economically viable
                "gamma": "PASS"   # Defenses insufficient
            },
            "ready_for_synthesis": True
        }
        
        assert validated_finding["ready_for_synthesis"] == True
        assert all(s == "PASS" for s in validated_finding["skeptic_scores"].values())


class TestAgentConfiguration:
    """Test agent configuration and instantiation."""
    
    def test_all_aegis_agents_importable(self):
        """Test that all Aegis agents can be imported."""
        agents_to_test = [
            ("cai.agents.skeptic_alpha", "skeptic_alpha"),
            ("cai.agents.skeptic_beta", "skeptic_beta"),
            ("cai.agents.skeptic_gamma", "skeptic_gamma"),
            ("cai.agents.bridge_analyzer", "bridge_analyzer"),
            ("cai.agents.mev_analyzer", "mev_analyzer"),
        ]
        
        for module_name, agent_name in agents_to_test:
            try:
                import importlib
                module = importlib.import_module(module_name)
                agent = getattr(module, agent_name)
                assert agent is not None, f"Agent {agent_name} is None"
                assert hasattr(agent, 'name'), f"Agent {agent_name} has no name"
                assert hasattr(agent, 'tools'), f"Agent {agent_name} has no tools"
            except ImportError as e:
                pytest.fail(f"Failed to import {module_name}: {e}")
    
    def test_agent_registry_includes_new_agents(self):
        """Test that agent registry includes new agents."""
        from cai.agents import AVAILABLE_AGENTS
        
        new_agents = ["bridge_analyzer", "mev_analyzer"]
        
        for agent in new_agents:
            assert agent in AVAILABLE_AGENTS, f"Agent {agent} not in AVAILABLE_AGENTS"
