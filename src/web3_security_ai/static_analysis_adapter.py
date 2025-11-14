#!/usr/bin/env python3

"""
Adapter layer for integrating static analysis tools (Slither, Mythril, Securify2).
This module provides a standardized interface for different security analysis tools.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging
from enum import Enum

from .base_agent import BaseAgent, AgentConfig, AgentType, AgentRole


class StaticAnalyzerType(Enum):
    """Types of static analyzers supported."""
    SLITHER = "slither"
    MYTHRIL = "mythril"
    SECURIFY2 = "securify2"
    SOLVER = "solver"


class AnalyzerResult:
    """Result from static analysis tools."""
    def __init__(self, analyzer_type: StaticAnalyzerType, findings: List[Dict[str, Any]], 
                 confidence: float, timestamp: float):
        self.analyzer_type = analyzer_type
        self.findings = findings
        self.confidence = confidence
        self.timestamp = timestamp


class StaticAnalysisAdapter:
    """Adapter for static analysis tools integration."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analyzers = {
            StaticAnalyzerType.SLITHER: self._run_slither,
            StaticAnalyzerType.MYTHRIL: self._run_mythril,
            StaticAnalyzerType.SECURIFY2: self._run_securify2,
            StaticAnalyzerType.SOLVER: self._run_solver
        }
        
    async def run_analysis(self, contract_source: str, analyzer_type: StaticAnalyzerType, 
                          parameters: Optional[Dict[str, Any]] = None) -> AnalyzerResult:
        """Run analysis using specified static analyzer.
        
        Args:
            contract_source: Source code to analyze
            analyzer_type: Type of analyzer to use
            parameters: Additional parameters for the analyzer
            
        Returns:
            Analysis results
        """
        if analyzer_type not in self.analyzers:
            raise ValueError(f"Unsupported analyzer type: {analyzer_type}")
        
        # Run the appropriate analyzer
        findings = await self.analyzers[analyzer_type](contract_source, parameters)
        
        # Calculate confidence (simplified)
        confidence = min(1.0, len(findings) * 0.15 + 0.1)
        
        return AnalyzerResult(
            analyzer_type=analyzer_type,
            findings=findings,
            confidence=confidence,
            timestamp=asyncio.get_event_loop().time()
        )
    
    async def _run_slither(self, contract_source: str, parameters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run Slither analysis.
        
        Args:
            contract_source: Source code to analyze
            parameters: Additional parameters
            
        Returns:
            List of findings
        """
        # Simulated Slither findings
        findings = []
        
        if contract_source:
            # Look for potential issues
            if "unchecked_call" in contract_source.lower():
                findings.append({
                    "type": "unchecked_call",
                    "severity": "high",
                    "message": "Unchecked external call detected",
                    "location": "Unknown",
                    "description": "An unchecked external call can lead to unexpected behavior or reentrancy issues"
                })
                
            if "send()" in contract_source:
                findings.append({
                    "type": "ether_send",
                    "severity": "medium",
                    "message": "Ether sending detected",
                    "location": "Unknown",
                    "description": "Use of send() for ether transfer may cause issues if recipient is a contract"
                })
                
            if "require(msg.sender == owner)" in contract_source:
                findings.append({
                    "type": "owner_access_control",
                    "severity": "medium",
                    "message": "Owner-only access control",
                    "location": "Unknown",
                    "description": "Access control restricted to owner, potential security issue"
                })
        
        return findings
    
    async def _run_mythril(self, contract_source: str, parameters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run Mythril analysis.
        
        Args:
            contract_source: Source code to analyze
            parameters: Additional parameters
            
        Returns:
            List of findings
        """
        # Simulated Mythril findings
        findings = []
        
        if contract_source:
            # Look for potential issues
            if "selfdestruct" in contract_source.lower():
                findings.append({
                    "type": "selfdestruct",
                    "severity": "high",
                    "message": "Selfdestruct call detected",
                    "location": "Unknown",
                    "description": "Selfdestruct can destroy the contract and its funds"
                })
                
            if "delegatecall" in contract_source.lower():
                findings.append({
                    "type": "delegatecall",
                    "severity": "high",
                    "message": "Delegatecall detected",
                    "location": "Unknown",
                    "description": "Delegatecall may lead to unexpected code execution"
                })
                
            if "tx.origin" in contract_source.lower():
                findings.append({
                    "type": "tx_origin",
                    "severity": "medium",
                    "message": "tx.origin usage detected",
                    "location": "Unknown",
                    "description": "Use of tx.origin is discouraged due to phishing risks"
                })
        
        return findings
    
    async def _run_securify2(self, contract_source: str, parameters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run Securify2 analysis.
        
        Args:
            contract_source: Source code to analyze
            parameters: Additional parameters
            
        Returns:
            List of findings
        """
        # Simulated Securify2 findings
        findings = []
        
        if contract_source:
            # Look for potential issues
            if "revert()" in contract_source.lower():
                findings.append({
                    "type": "revert",
                    "severity": "low",
                    "message": "Revert statement detected",
                    "location": "Unknown",
                    "description": "Revert statements are acceptable but should be used appropriately"
                })
                
            if "block.timestamp" in contract_source.lower():
                findings.append({
                    "type": "timestamp",
                    "severity": "medium",
                    "message": "Timestamp dependency detected",
                    "location": "Unknown",
                    "description": "Use of block.timestamp can be manipulated by miners"
                })
        
        return findings
    
    async def _run_solver(self, contract_source: str, parameters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run solver analysis (generic checks).
        
        Args:
            contract_source: Source code to analyze
            parameters: Additional parameters
            
        Returns:
            List of findings
        """
        # Simulated solver findings
        findings = []
        
        if contract_source:
            # Look for potential issues
            if "div" in contract_source.lower():
                findings.append({
                    "type": "division",
                    "severity": "medium",
                    "message": "Division operation detected",
                    "location": "Unknown",
                    "description": "Division by zero can cause revert if divisor is zero"
                })
        
        return findings
    
    def combine_results(self, results: List[AnalyzerResult]) -> Dict[str, Any]:
        """Combine results from multiple analyzers.
        
        Args:
            results: List of analyzer results
            
        Returns:
            Combined results
        """
        all_findings = []
        total_confidence = 0.0
        analyzer_count = len(results)
        
        for result in results:
            all_findings.extend(result.findings)
            total_confidence += result.confidence
            
        avg_confidence = total_confidence / analyzer_count if analyzer_count > 0 else 0.0
        
        # Categorize findings by severity
        severity_counts = {}
        for finding in all_findings:
            severity = finding.get("severity", "unknown")
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
        
        return {
            "findings": all_findings,
            "total_findings": len(all_findings),
            "analyzer_count": analyzer_count,
            "average_confidence": avg_confidence,
            "severity_breakdown": severity_counts
        }
