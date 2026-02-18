"""
Unit tests for MEV Analyzer Agent

Tests the MEV (Maximal Extractable Value) vulnerability analysis capabilities
including sandwich attacks, frontrunning, backrunning, and MEV exposure calculation.
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestMEVAnalyzer:
    """Test suite for MEV Analyzer agent tools."""
    
    @pytest.fixture
    def sample_vulnerable_swap_code(self):
        """Sample vulnerable DEX swap code."""
        return '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        contract VulnerableSwap {
            function swap(
                address tokenIn,
                address tokenOut,
                uint256 amountIn
            ) external returns (uint256 amountOut) {
                // No slippage protection - sandwich vulnerable
                // No deadline - can be delayed indefinitely
                
                // Calculate output based on reserves
                amountOut = getAmountOut(amountIn);
                
                // Transfer tokens
                // ...
            }
            
            function liquidate(address borrower) external {
                // Publicly visible liquidation - frontrun vulnerable
                // ...
            }
        }
        '''
    
    @pytest.fixture
    def sample_protected_swap_code(self):
        """Sample protected DEX swap code."""
        return '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        contract ProtectedSwap {
            function swap(
                address tokenIn,
                address tokenOut,
                uint256 amountIn,
                uint256 amountOutMin,
                uint256 deadline
            ) external returns (uint256 amountOut) {
                require(block.timestamp <= deadline, "Expired");
                
                // Calculate output
                amountOut = getAmountOut(amountIn);
                
                // Slippage protection
                require(amountOut >= amountOutMin, "Slippage");
                
                // Check price impact
                uint256 priceImpact = calculatePriceImpact(amountIn);
                require(priceImpact <= MAX_PRICE_IMPACT, "Too much impact");
                
                // Transfer tokens
                // ...
            }
        }
        '''
    
    def test_analyze_sandwich_vulnerability_vulnerable(self, sample_vulnerable_swap_code):
        """Test sandwich attack analysis on vulnerable code."""
        from cai.agents.mev_analyzer import analyze_sandwich_vulnerability
        
        result_json = analyze_sandwich_vulnerability(sample_vulnerable_swap_code)
        result = json.loads(result_json)
        
        assert result["verdict"] == "VULNERABLE"
        assert result["has_slippage_protection"] == False
        assert result["has_deadline"] == False
        assert result["findings_count"] > 0
        assert any(f["severity"] == "CRITICAL" for f in result["findings"])
    
    def test_analyze_sandwich_vulnerability_protected(self, sample_protected_swap_code):
        """Test sandwich attack analysis on protected code."""
        from cai.agents.mev_analyzer import analyze_sandwich_vulnerability
        
        result_json = analyze_sandwich_vulnerability(sample_protected_swap_code)
        result = json.loads(result_json)
        
        assert result["has_slippage_protection"] == True
        assert result["has_deadline"] == True
        assert result["has_price_impact_calc"] == True
    
    def test_analyze_frontrun_vulnerability(self, sample_vulnerable_swap_code):
        """Test frontrunning analysis."""
        from cai.agents.mev_analyzer import analyze_frontrun_vulnerability
        
        result_json = analyze_frontrun_vulnerability(sample_vulnerable_swap_code)
        result = json.loads(result_json)
        
        assert result["has_liquidation"] == True
        assert result["findings_count"] > 0
        assert any(f["mev_type"] == "frontrun" for f in result["findings"])
    
    def test_analyze_backrun_opportunity(self, sample_vulnerable_swap_code):
        """Test backrunning analysis."""
        from cai.agents.mev_analyzer import analyze_backrun_opportunity
        
        result_json = analyze_backrun_opportunity(sample_vulnerable_swap_code)
        result = json.loads(result_json)
        
        assert "backrun_risk" in result
        assert "findings" in result
    
    def test_calculate_mev_exposure_swap(self):
        """Test MEV exposure calculation for swap."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        result_json = calculate_mev_exposure(
            function_type="swap",
            trade_size_eth=10.0,
            pool_liquidity_eth=1000.0,
            gas_price_gwei=50.0
        )
        result = json.loads(result_json)
        
        assert result["function_type"] == "swap"
        assert result["trade_size_eth"] == 10.0
        assert result["price_impact_percent"] == 1.0  # 10/1000 * 100
        assert "potential_mev_eth" in result
        assert "mev_profitable" in result
    
    def test_calculate_mev_exposure_liquidation(self):
        """Test MEV exposure calculation for liquidation."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        result_json = calculate_mev_exposure(
            function_type="liquidation",
            trade_size_eth=100.0,
            pool_liquidity_eth=10000.0,
            gas_price_gwei=30.0
        )
        result = json.loads(result_json)
        
        assert result["function_type"] == "liquidation"
        assert result["mev_multiplier"] == 0.8  # Liquidation multiplier
        assert result["mev_profitable"] == True  # Should be profitable
    
    def test_calculate_mev_exposure_small_trade(self):
        """Test MEV exposure for small trade (unprofitable)."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        result_json = calculate_mev_exposure(
            function_type="swap",
            trade_size_eth=0.01,  # Very small trade
            pool_liquidity_eth=1000.0,
            gas_price_gwei=100.0  # High gas
        )
        result = json.loads(result_json)
        
        # Small trade with high gas should not be profitable for MEV
        assert result["risk_level"] == "LOW"
    
    def test_suggest_mev_mitigations(self):
        """Test MEV mitigation suggestions."""
        from cai.agents.mev_analyzer import suggest_mev_mitigations
        
        vulnerabilities = [
            "SANDWICH_NO_SLIPPAGE",
            "FRONTRUN_LIQUIDATION",
            "ORACLE_STALE"
        ]
        
        result_json = suggest_mev_mitigations(vulnerabilities, "defi")
        result = json.loads(result_json)
        
        assert result["vulnerabilities_addressed"] == 3
        assert len(result["mitigations"]) > 0
        assert "general_recommendations" in result
    
    def test_render_mev_report(self):
        """Test MEV report generation."""
        from cai.agents.mev_analyzer import render_mev_report
        
        sandwich_findings = [
            {"issue": "NO_SLIPPAGE", "severity": "CRITICAL", "description": "Test"}
        ]
        frontrun_findings = []
        backrun_findings = []
        mev_exposure = {
            "trade_size_eth": 10.0,
            "price_impact_percent": 1.0,
            "potential_mev_eth": 0.05,
            "potential_mev_usd": 100.0,
            "net_mev_eth": 0.04,
            "mev_profitable": True
        }
        
        report = render_mev_report(
            "TestSwap",
            sandwich_findings,
            frontrun_findings,
            backrun_findings,
            mev_exposure
        )
        
        assert "TestSwap" in report
        assert "CRITICAL" in report
        assert "MEV Risk" in report
        assert "Sandwich" in report


class TestMEVAnalyzerAgent:
    """Test suite for MEV Analyzer agent instantiation."""
    
    def test_agent_creation(self):
        """Test that the agent can be created."""
        from cai.agents.mev_analyzer import mev_analyzer
        
        assert mev_analyzer is not None
        assert mev_analyzer.name == "MEV Analyzer"
        assert len(mev_analyzer.tools) > 0
    
    def test_agent_has_required_tools(self):
        """Test that agent has all required tools."""
        from cai.agents.mev_analyzer import mev_analyzer
        
        tool_names = [t.name for t in mev_analyzer.tools]
        
        required_tools = [
            "analyze_sandwich_vulnerability",
            "analyze_frontrun_vulnerability",
            "analyze_backrun_opportunity",
            "calculate_mev_exposure",
            "suggest_mev_mitigations",
            "render_mev_report",
        ]
        
        for tool in required_tools:
            assert tool in tool_names, f"Missing tool: {tool}"
    
    def test_agent_description(self):
        """Test agent description is informative."""
        from cai.agents.mev_analyzer import mev_analyzer
        
        assert "mev" in mev_analyzer.description.lower()
        assert "sandwich" in mev_analyzer.description.lower()


class TestMEVExposureCalculations:
    """Test suite for MEV exposure calculations edge cases."""
    
    def test_zero_liquidity(self):
        """Test handling of zero liquidity pool."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        # Should handle division by zero gracefully
        result_json = calculate_mev_exposure(
            function_type="swap",
            trade_size_eth=10.0,
            pool_liquidity_eth=0.0,  # Zero liquidity
            gas_price_gwei=50.0
        )
        result = json.loads(result_json)
        
        # Should either return error or handle gracefully
        assert "error" in result or "price_impact_percent" in result
    
    def test_negative_values(self):
        """Test handling of negative values."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        result_json = calculate_mev_exposure(
            function_type="swap",
            trade_size_eth=-10.0,  # Negative trade
            pool_liquidity_eth=1000.0,
            gas_price_gwei=50.0
        )
        result = json.loads(result_json)
        
        # Should handle gracefully
        assert "trade_size_eth" in result or "error" in result
    
    def test_unknown_function_type(self):
        """Test handling of unknown function type."""
        from cai.agents.mev_analyzer import calculate_mev_exposure
        
        result_json = calculate_mev_exposure(
            function_type="unknown_type",
            trade_size_eth=10.0,
            pool_liquidity_eth=1000.0,
            gas_price_gwei=50.0
        )
        result = json.loads(result_json)
        
        # Should use default multiplier
        assert result["mev_multiplier"] == 0.3  # Default
