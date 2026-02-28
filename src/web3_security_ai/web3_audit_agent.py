#!/usr/bin/env python3

"""
Web3 Audit Agent for the Security System.
Specialized agent for analyzing smart contracts and blockchain protocols.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging
import hashlib
import re
import os

from .base_agent import BaseAgent, AgentConfig, AgentType, AgentRole
from cai.core.finding import Finding
from cai.tools.web3_security import (
    slither_analyze, 
    slitheryn_print,
    analyze_precision_vulnerabilities,
    score_exploit_viability
)


class ContractAnalysisResult:
    """Result of contract analysis."""
    def __init__(self, contract_address: str, findings: List[Dict[str, Any]], 
                 confidence_score: float, vulnerabilities: List[str]):
        self.contract_address = contract_address
        self.findings = findings
        self.confidence_score = confidence_score
        self.vulnerabilities = vulnerabilities
        self.analysis_timestamp = asyncio.get_event_loop().time()


class Web3AuditAgent(BaseAgent):
    """Specialized agent for Web3 security auditing."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.contract_cache = {}  # Cache for previously analyzed contracts
        
    async def initialize(self) -> bool:
        """Initialize the Web3 audit agent."""
        self.is_active = True
        self.logger.info(f"Web3 Audit Agent {self.name} initialized")
        return True
    
    async def cleanup(self) -> None:
        """Clean up the Web3 audit agent."""
        self.is_active = False
        self.logger.info(f"Web3 Audit Agent {self.name} cleaned up")
    
    async def execute_task(self, task: str, **kwargs) -> List[Finding]:
        """Execute a Web3 audit task and return List[Finding].
        
        Args:
            task: Description of task to execute
            **kwargs: Additional parameters
            
        Returns:
            List of Finding objects
        """
        try:
            # Parse the task
            task_data = json.loads(task) if isinstance(task, str) else task
            
            # Extract contract information
            contract_address = task_data.get("contract_address", "0x0")
            contract_path = task_data.get("contract_path")
            contract_source = task_data.get("contract_source")
            
            if not contract_path and not contract_source:
                raise ValueError("Contract path or source is required")
            
            # If source provided but no path, save to temp file
            if contract_source and not contract_path:
                contract_path = "/tmp/audit_target.sol"
                with open(contract_path, "w") as f:
                    f.write(contract_source)
            
            # Perform the analysis
            findings = await self._analyze_contract(contract_address, contract_path, **kwargs)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error in Web3 audit task: {str(e)}")
            return []
    
    async def _analyze_contract(self, contract_address: str, contract_path: str, **kwargs) -> List[Finding]:
        """Perform the actual contract analysis using Slither.
        
        Args:
            contract_address: Address of the contract to analyze
            contract_path: Path to the contract file or project
            **kwargs: Additional parameters
            
        Returns:
            List of Finding objects
        """
        self.logger.info(f"Analyzing contract {contract_address} at {contract_path}")
        
        findings_objects = []
        
        # 1. Slither Static Analysis (JSON output)
        json_output = "/tmp/slither_results.json"
        slither_analyze(contract_path, json_output=json_output)
        
        if os.path.exists(json_output):
            with open(json_output, "r") as f:
                try:
                    slither_data = json.load(f)
                    if "results" in slither_data and "detectors" in slither_data["results"]:
                        for detector in slither_data["results"]["detectors"]:
                            detector_name = detector.get("check", "unknown")
                            severity = detector.get("impact", "medium")
                            
                            for element in detector.get("elements", []):
                                f_id = f"{detector_name}_{hashlib.md_str(str(element)).hexdigest()[:8]}" if hasattr(hashlib, 'md_str') else f"{detector_name}_{hashlib.md5(str(element).encode()).hexdigest()[:8]}"
                                
                                finding = Finding(
                                    id=f_id,
                                    vulnerability_type=detector_name,
                                    severity=severity,
                                    contract=element.get("contract", {}).get("name", "unknown") if isinstance(element.get("contract"), dict) else element.get("contract", "unknown"),
                                    function_name=element.get("name", "unknown"),
                                    location=f"{element.get('source_mapping', {}).get('filename_short')}:{element.get('source_mapping', {}).get('lines')}"
                                )
                                
                                # Extract additional context
                                if "external_calls" in element:
                                    finding.external_call_depth = len(element["external_calls"])
                                    finding.cross_contract = any(c.get("type") == "external" for c in element["external_calls"])
                                
                                findings_objects.append(finding)
                except Exception as e:
                    self.logger.error(f"Error parsing Slither JSON: {e}")

        # 2. Extract Call Graph and External Call Targets (using printers)
        # In a real implementation, we would parse the output of these printers
        # slitheryn_print(contract_path, printer="call-graph")
        # slitheryn_print(contract_path, printer="vars-and-auth")
        
        # 3. Precision Analysis
        if os.path.exists(contract_path) and os.path.isfile(contract_path):
            with open(contract_path, "r") as f:
                source = f.read()
                precision_results_json = analyze_precision_vulnerabilities(source)
                precision_results = json.loads(precision_results_json)
                
                for cat in precision_results.get("categories", []):
                    for f_p in cat.get("findings", []):
                        findings_objects.append(Finding(
                            id=f"precision_{hashlib.md5(f_p.get('description', '').encode()).hexdigest()[:8]}",
                            vulnerability_type="precision_loss",
                            severity=f_p.get("severity", "medium"),
                            contract=contract_address,
                            function_name="unknown",
                            location=str(f_p.get("line_number", "0"))
                        ))

        return findings_objects
    
    def get_contract_summary(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """Get a summary of a contract from cache.
        
        Args:
            contract_address: Address of the contract
            
        Returns:
            Summary of the contract analysis or None if not found
        """
        cache_key = f"{contract_address}_full"
        return self.contract_cache.get(cache_key)
    
    def clear_cache(self) -> None:
        """Clear the contract analysis cache."""
        self.contract_cache.clear()
        self.logger.info("Contract analysis cache cleared")
