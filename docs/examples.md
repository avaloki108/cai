# Code Examples and Sample Usage

This document provides comprehensive code examples for using the Web3 Security Auditing AI System, from basic usage to advanced custom agent development.

## Table of Contents

- [Basic Usage Examples](#basic-usage-examples)
- [Custom Agent Development](#custom-agent-development)
- [External Tool Integration](#external-tool-integration)
- [Configuration Examples](#configuration-examples)
- [Advanced Usage Patterns](#advanced-usage-patterns)
- [Integration Examples](#integration-examples)

---

## Basic Usage Examples

### Example 1: Simple Smart Contract Audit

```python
#!/usr/bin/env python3
"""
Basic smart contract auditing example.
This example demonstrates how to perform a basic security audit on a smart contract.
"""

from web3_security_ai import Web3SecurityAuditor

def main():
    # Initialize the auditor
    auditor = Web3SecurityAuditor()

    # Sample vulnerable contract
    contract_code = '''
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // BUG: State change after external call
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[to] += amount; // BUG: No overflow check in older Solidity
        balances[msg.sender] -= amount;
    }
}
'''

    print("🔍 Starting smart contract audit...")
    print("=" * 50)

    try:
        # Run the audit
        results = auditor.audit_contract(contract_code)

        # Display results
        print(f"📊 Audit Summary:")
        print(f"   Total Findings: {len(results.get('vulnerabilities', []))}")
        print()

        # Display each finding
        for i, finding in enumerate(results.get('vulnerabilities', []), 1):
            print(f"🚨 Finding {i}: {finding.get('title', 'Unknown')}")
            print(f"   Severity: {finding.get('severity', 'Unknown')}")
            print(f"   Type: {finding.get('type', 'Unknown')}")
            print(f"   Description: {finding.get('description', 'No description')}")
            print(f"   Impact: {finding.get('impact', 'Unknown')}")
            print(f"   Recommendation: {finding.get('recommendation', 'No recommendation')}")
            print()

    except Exception as e:
        print(f"❌ Audit failed: {str(e)}")
        return 1

    print("✅ Audit completed successfully!")
    return 0

if __name__ == "__main__":
    exit(main())
```

### Example 2: Command Line Audit

```bash
#!/bin/bash
# Command line audit examples

# Basic contract audit
web3-audit audit contracts/Token.sol --output audit_results.json

# Comprehensive audit with multiple tools
web3-audit audit contracts/ --comprehensive \
    --tools slither,mythril \
    --format pdf \
    --output comprehensive_audit.pdf

# Audit with custom configuration
web3-audit audit contracts/DeFiProtocol.sol \
    --config audit_config.yaml \
    --parallel \
    --timeout 600

# Batch audit multiple contracts
web3-audit audit contracts/*.sol \
    --batch \
    --output-dir audit_results/

# Check audit status
web3-audit status audit_12345

# Generate report from existing results
web3-audit report audit_12345 \
    --format json,pdf,html \
    --include-source
```

### Example 3: DeFi Protocol Audit

```python
#!/usr/bin/env python3
"""
DeFi Protocol auditing example.
This example shows how to audit a complete DeFi protocol with multiple contracts.
"""

from web3_security_ai.orchestrator import AuditOrchestrator
from web3_security_ai.agents import DeFiAuditAgent, LiquidityAnalysisAgent
from pathlib import Path
import json

def audit_defi_protocol(protocol_path: str) -> dict:
    """
    Perform comprehensive audit of a DeFi protocol.

    Args:
        protocol_path: Path to the protocol directory

    Returns:
        Audit results dictionary
    """

    # Initialize specialized agents
    agents = [
        DeFiAuditAgent(),
        LiquidityAnalysisAgent()
    ]

    # Create orchestrator
    orchestrator = AuditOrchestrator(agents)

    # Define protocol configuration
    protocol_config = {
        "name": "Sample DeFi Protocol",
        "contracts": [
            f"{protocol_path}/contracts/core/*.sol",
            f"{protocol_path}/contracts/periphery/*.sol"
        ],
        "networks": ["ethereum", "polygon"],
        "analysis_depth": "comprehensive",
        "check_flash_loans": True,
        "verify_oracle_security": True,
        "analyze_impermanent_loss": True
    }

    print(f"🔍 Auditing DeFi protocol: {protocol_config['name']}")
    print("=" * 60)

    try:
        # Run comprehensive audit
        report = orchestrator.run_full_audit(protocol_config)

        # Display summary
        summary = report.summary
        print("📊 Audit Summary:"        print(f"   Total Contracts: {len(protocol_config['contracts'])}")
        print(f"   Total Findings: {summary.total_findings}")
        print(f"   Critical: {summary.critical}")
        print(f"   High: {summary.high}")
        print(f"   Medium: {summary.medium}")
        print(f"   Low: {summary.low}")
        print(f"   Risk Score: {summary.risk_score:.1f}/10")
        print()

        # Display top findings
        print("🚨 Top Security Findings:")
        for finding in report.findings[:5]:  # Show top 5
            print(f"   • {finding.severity.upper()}: {finding.title}")
            print(f"     {finding.description[:100]}...")

        return {
            "success": True,
            "report": report,
            "summary": summary
        }

    except Exception as e:
        print(f"❌ Audit failed: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

def main():
    import sys

    if len(sys.argv) != 2:
        print("Usage: python defi_audit.py <protocol_path>")
        return 1

    protocol_path = sys.argv[1]

    if not Path(protocol_path).exists():
        print(f"❌ Protocol path does not exist: {protocol_path}")
        return 1

    results = audit_defi_protocol(protocol_path)

    if results["success"]:
        # Save detailed report
        output_file = f"{protocol_path}/audit_report.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"📄 Detailed report saved to: {output_file}")

    return 0 if results["success"] else 1

if __name__ == "__main__":
    exit(main())
```

---

## Custom Agent Development

### Example 4: Custom Security Agent

```python
#!/usr/bin/env python3
"""
Custom security agent development example.
This example shows how to create a specialized security agent.
"""

from web3_security_ai.sdk import BaseAuditAgent, AgentConfig
from web3_security_ai.tools import CodeAnalyzer, PatternMatcher
from web3_security_ai.models import Finding, Severity
from typing import List, Dict, Any
import re

class CustomSecurityAgent(BaseAuditAgent):
    """
    Custom security agent for specialized vulnerability detection.
    This agent focuses on domain-specific security patterns.
    """

    def __init__(self, config: AgentConfig = None):
        super().__init__(
            name="Custom Security Agent",
            description="Specialized agent for custom security checks",
            config=config or AgentConfig()
        )

        # Initialize tools
        self.code_analyzer = CodeAnalyzer()
        self.pattern_matcher = PatternMatcher()

        # Define custom vulnerability patterns
        self.vulnerability_patterns = {
            "unchecked_send": {
                "pattern": r"\.send\s*\(\s*\w+\s*\)",
                "severity": Severity.HIGH,
                "description": "Use of .send() without return value check",
                "recommendation": "Use .call() with proper error handling or require success check"
            },
            "tx_origin": {
                "pattern": r"tx\.origin",
                "severity": Severity.MEDIUM,
                "description": "Use of tx.origin for authorization",
                "recommendation": "Use msg.sender for authorization checks"
            },
            "magic_numbers": {
                "pattern": r"=\s*\d{4,}",  # Numbers with 4+ digits
                "severity": Severity.LOW,
                "description": "Magic numbers in code",
                "recommendation": "Use named constants instead of magic numbers"
            }
        }

    def analyze_contract(self, contract_code: str, context: Dict[str, Any] = None) -> List[Finding]:
        """
        Analyze contract code for custom vulnerabilities.

        Args:
            contract_code: The contract source code
            context: Additional analysis context

        Returns:
            List of security findings
        """
        findings = []

        try:
            # Run custom pattern analysis
            pattern_findings = self._analyze_patterns(contract_code)
            findings.extend(pattern_findings)

            # Run code structure analysis
            structure_findings = self._analyze_code_structure(contract_code)
            findings.extend(structure_findings)

            # Run business logic analysis
            logic_findings = self._analyze_business_logic(contract_code, context)
            findings.extend(logic_findings)

        except Exception as e:
            # Create error finding
            error_finding = Finding(
                id=f"analysis_error_{hash(contract_code) % 10000}",
                type="analysis_error",
                severity=Severity.INFO,
                confidence="high",
                title="Analysis Error",
                description=f"Failed to complete analysis: {str(e)}",
                location=None,
                code_snippet="",
                impact="Analysis may be incomplete",
                recommendation="Review analysis logs and retry",
                cvss_score=0.0,
                references=[],
                metadata={"error": str(e)}
            )
            findings.append(error_finding)

        return findings

    def _analyze_patterns(self, contract_code: str) -> List[Finding]:
        """Analyze code for pattern-based vulnerabilities."""
        findings = []

        for vuln_name, vuln_config in self.vulnerability_patterns.items():
            matches = re.finditer(vuln_config["pattern"], contract_code, re.MULTILINE)

            for match in matches:
                # Get line number
                line_num = contract_code[:match.start()].count('\n') + 1

                # Extract code snippet
                lines = contract_code.split('\n')
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 3)
                snippet = '\n'.join(lines[start_line:end_line])

                finding = Finding(
                    id=f"{vuln_name}_{line_num}_{hash(match.group()) % 10000}",
                    type=vuln_name,
                    severity=vuln_config["severity"],
                    confidence="high",
                    title=vuln_config["description"],
                    description=vuln_config["description"],
                    location={
                        "file": "contract.sol",
                        "line": line_num,
                        "column": match.start() - contract_code.rfind('\n', 0, match.start())
                    },
                    code_snippet=snippet,
                    impact=self._determine_impact(vuln_name),
                    recommendation=vuln_config["recommendation"],
                    cvss_score=self._calculate_cvss(vuln_config["severity"]),
                    references=self._get_references(vuln_name),
                    metadata={"pattern": vuln_config["pattern"]}
                )
                findings.append(finding)

        return findings

    def _analyze_code_structure(self, contract_code: str) -> List[Finding]:
        """Analyze code structure for potential issues."""
        findings = []

        # Check for missing access controls
        if "function" in contract_code and "onlyOwner" not in contract_code:
            finding = Finding(
                id=f"missing_access_control_{hash(contract_code) % 10000}",
                type="access_control",
                severity=Severity.MEDIUM,
                confidence="medium",
                title="Potential Missing Access Control",
                description="Contract contains functions that may lack proper access control",
                location={"file": "contract.sol", "line": 1, "column": 1},
                code_snippet="",
                impact="Unauthorized access to sensitive functions",
                recommendation="Implement proper access control modifiers",
                cvss_score=5.0,
                references=["https://swcregistry.io/docs/SWC-105"],
                metadata={}
            )
            findings.append(finding)

        return findings

    def _analyze_business_logic(self, contract_code: str, context: Dict[str, Any] = None) -> List[Finding]:
        """Analyze business logic for domain-specific issues."""
        findings = []

        # Context-aware analysis
        if context and context.get("contract_type") == "token":
            # Token-specific checks
            if "transfer" in contract_code and "balances" in contract_code:
                # Check for overflow protection
                if "_safe" not in contract_code and "SafeMath" not in contract_code:
                    finding = Finding(
                        id=f"overflow_risk_{hash(contract_code) % 10000}",
                        type="overflow",
                        severity=Severity.HIGH,
                        confidence="medium",
                        title="Potential Arithmetic Overflow",
                        description="Token contract may be vulnerable to arithmetic overflow",
                        location={"file": "contract.sol", "line": 1, "column": 1},
                        code_snippet="",
                        impact="Loss of token accounting integrity",
                        recommendation="Use SafeMath library or Solidity 0.8+ built-in checks",
                        cvss_score=7.0,
                        references=["https://swcregistry.io/docs/SWC-101"],
                        metadata={"contract_type": "token"}
                    )
                    findings.append(finding)

        return findings

    def _determine_impact(self, vuln_type: str) -> str:
        """Determine the impact of a vulnerability."""
        impacts = {
            "unchecked_send": "Potential loss of ether due to failed transfers",
            "tx_origin": "Authorization bypass through phishing attacks",
            "magic_numbers": "Code maintainability and potential logic errors"
        }
        return impacts.get(vuln_type, "Unknown impact")

    def _calculate_cvss(self, severity: Severity) -> float:
        """Calculate CVSS score based on severity."""
        scores = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0
        }
        return scores.get(severity, 0.0)

    def _get_references(self, vuln_type: str) -> List[str]:
        """Get reference links for vulnerability type."""
        references = {
            "unchecked_send": ["https://swcregistry.io/docs/SWC-104"],
            "tx_origin": ["https://swcregistry.io/docs/SWC-115"],
            "magic_numbers": ["https://wiki.sei.cmu.edu/confluence/display/java/DCL00-J.+Prevent+class+initialization+cycles"]
        }
        return references.get(vuln_type, [])

# Usage example
def main():
    # Create custom agent
    agent = CustomSecurityAgent()

    # Sample contract with vulnerabilities
    contract = '''
pragma solidity ^0.7.0; // Old version, potential overflow

contract MyToken {
    mapping(address => uint256) balances;

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[to] += amount; // Potential overflow
        balances[msg.sender] -= amount;
    }

    function sendEther(address payable recipient, uint256 amount) public {
        recipient.send(amount); // Unchecked send
    }

    function checkOwner() public view returns (bool) {
        return tx.origin == owner; // Wrong authorization
    }
}
'''

    # Run analysis
    findings = agent.analyze_contract(contract)

    print(f"🔍 Custom Agent Analysis Results:")
    print(f"   Findings: {len(findings)}")
    print()

    for finding in findings:
        print(f"🚨 {finding.severity.upper()}: {finding.title}")
        print(f"   {finding.description}")
        print(f"   💡 {finding.recommendation}")
        print()

if __name__ == "__main__":
    main()
```

### Example 5: Plugin Development

```python
#!/usr/bin/env python3
"""
Plugin development example.
This example shows how to create a plugin that extends the auditing system.
"""

from web3_security_ai.plugins import BasePlugin, PluginManager
from web3_security_ai.tools import BaseTool
from web3_security_ai.agents import BaseAuditAgent
import requests

class APISecurityTool(BaseTool):
    """Tool for API security testing."""

    def __init__(self):
        super().__init__(
            name="API Security Scanner",
            description="Scans APIs for common security vulnerabilities"
        )

    def run_analysis(self, target: str) -> dict:
        """Run API security analysis."""
        # Implementation for API security scanning
        return {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "scan_duration": 0
        }

class APISecurityAgent(BaseAuditAgent):
    """Agent specialized in API security."""

    def __init__(self):
        super().__init__(
            name="API Security Agent",
            description="Specialized agent for API security analysis"
        )
        self.api_tool = APISecurityTool()

    def analyze(self, target: str) -> list:
        """Analyze target for API security issues."""
        return self.api_tool.run_analysis(target)

class CustomAuditPlugin(BasePlugin):
    """
    Custom audit plugin that adds API security capabilities.
    """

    name = "api_security_plugin"
    version = "1.0.0"
    description = "Extends auditing system with API security capabilities"

    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self.api_agent = APISecurityAgent()
        self.api_tool = APISecurityTool()

    def initialize(self):
        """Initialize the plugin."""
        print(f"🔌 Initializing {self.name} v{self.version}")

        # Register new tool
        self.plugin_manager.register_tool(self.api_tool)

        # Register new agent
        self.plugin_manager.register_agent(self.api_agent)

        # Register event handlers
        self.plugin_manager.register_hook(
            'audit_started',
            self.on_audit_started
        )

        self.plugin_manager.register_hook(
            'audit_completed',
            self.on_audit_completed
        )

    def on_audit_started(self, event_data: dict):
        """Handle audit started event."""
        target = event_data.get('target', 'unknown')
        print(f"🔍 API Security Plugin: Starting audit for {target}")

        # Check if target is an API
        if self._is_api_target(target):
            print("   📡 Detected API target, enabling API security checks")

    def on_audit_completed(self, event_data: dict):
        """Handle audit completed event."""
        audit_id = event_data.get('audit_id')
        findings = event_data.get('findings', [])

        api_findings = [f for f in findings if f.get('type', '').startswith('api_')]

        if api_findings:
            print(f"🔍 API Security Plugin: Found {len(api_findings)} API-related findings")
            for finding in api_findings:
                print(f"   🚨 {finding.get('severity', 'unknown')}: {finding.get('title', 'unknown')}")

    def _is_api_target(self, target: str) -> bool:
        """Check if target appears to be an API."""
        api_indicators = [
            'api.', '.api', '/api/', '/v1/', '/v2/',
            'swagger', 'openapi', 'graphql'
        ]
        return any(indicator in target.lower() for indicator in api_indicators)

    def get_capabilities(self) -> dict:
        """Return plugin capabilities."""
        return {
            "tools": [self.api_tool.name],
            "agents": [self.api_agent.name],
            "supported_targets": ["api", "web_service", "microservice"],
            "vulnerability_types": [
                "api_injection",
                "broken_authentication",
                "excessive_data_exposure",
                "rate_limiting_bypass",
                "cors_misconfiguration"
            ]
        }

# Plugin registration function
def register_plugin(plugin_manager: PluginManager):
    """Register the custom plugin."""
    plugin = CustomAuditPlugin(plugin_manager)
    plugin_manager.register_plugin(plugin)
    return plugin

# Usage example
if __name__ == "__main__":
    from web3_security_ai.plugins import PluginManager

    # Create plugin manager
    plugin_manager = PluginManager()

    # Register custom plugin
    plugin = register_plugin(plugin_manager)

    # Display plugin information
    print(f"📦 Registered Plugin: {plugin.name}")
    print(f"   Version: {plugin.version}")
    print(f"   Description: {plugin.description}")
    print(f"   Capabilities: {plugin.get_capabilities()}")
```

---

## External Tool Integration

### Example 6: Integrating Third-Party Tools

```python
#!/usr/bin/env python3
"""
External tool integration example.
This example shows how to integrate third-party security tools.
"""

import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from web3_security_ai.tools import BaseTool
from web3_security_ai.models import Finding, Severity

class SlitherTool(BaseTool):
    """Integration with Slither static analysis tool."""

    def __init__(self, slither_path: str = "slither"):
        super().__init__(
            name="Slither",
            description="Static analysis tool for Solidity smart contracts"
        )
        self.slither_path = slither_path

    def run_analysis(self, target: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run Slither analysis on target contract.

        Args:
            target: Path to contract file or directory
            config: Analysis configuration

        Returns:
            Analysis results
        """
        config = config or {}

        # Prepare command
        cmd = [self.slither_path, target, "--json", "-"]

        # Add configuration options
        if config.get("exclude_dependencies"):
            cmd.append("--exclude-dependencies")

        if config.get("foundry_ignore_compile"):
            cmd.append("--foundry-ignore-compile")

        detectors = config.get("detectors", [])
        if detectors:
            for detector in detectors:
                cmd.extend(["--detect", detector])

        try:
            # Run Slither
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.get("timeout", 300)
            )

            if result.returncode == 0:
                # Parse JSON output
                findings = self._parse_slither_output(result.stdout)
                return {
                    "success": True,
                    "findings": findings,
                    "raw_output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr,
                    "raw_output": result.stdout
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Analysis timed out"
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Slither not found at {self.slither_path}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Analysis failed: {str(e)}"
            }

    def _parse_slither_output(self, output: str) -> List[Finding]:
        """Parse Slither JSON output into standardized findings."""
        findings = []

        try:
            data = json.loads(output)

            for result in data.get("results", {}).get("detectors", []):
                # Convert Slither finding to standardized format
                finding = Finding(
                    id=f"slither_{result.get('check', 'unknown')}_{hash(str(result)) % 10000}",
                    type=result.get("check", "unknown"),
                    severity=self._map_severity(result.get("impact", "unknown")),
                    confidence=self._map_confidence(result.get("confidence", "unknown")),
                    title=result.get("title", "Unknown finding"),
                    description=result.get("description", ""),
                    location=self._parse_location(result.get("elements", [])),
                    code_snippet="",  # Would need to extract from source
                    impact=result.get("impact", "unknown"),
                    recommendation="",  # Slither doesn't provide recommendations
                    cvss_score=self._calculate_cvss_score(result),
                    references=[],
                    metadata={
                        "tool": "slither",
                        "check": result.get("check"),
                        "raw_result": result
                    }
                )
                findings.append(finding)

        except json.JSONDecodeError:
            # Handle non-JSON output
            pass

        return findings

    def _map_severity(self, slither_impact: str) -> Severity:
        """Map Slither impact to standardized severity."""
        mapping = {
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Informational": Severity.INFO
        }
        return mapping.get(slither_impact, Severity.INFO)

    def _map_confidence(self, slither_confidence: str) -> str:
        """Map Slither confidence to standardized confidence."""
        mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low"
        }
        return mapping.get(slither_confidence, "medium")

    def _parse_location(self, elements: List[Dict]) -> Optional[Dict]:
        """Parse Slither location information."""
        if not elements:
            return None

        # Extract first element's location
        element = elements[0]
        source_mapping = element.get("source_mapping", {})

        return {
            "file": source_mapping.get("filename_relative", "unknown"),
            "line": source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0,
            "column": 0
        }

    def _calculate_cvss_score(self, result: Dict) -> float:
        """Calculate CVSS score from Slither result."""
        impact = result.get("impact", "Low")
        confidence = result.get("confidence", "Medium")

        # Simple scoring based on impact and confidence
        base_scores = {
            "High": 7.0,
            "Medium": 5.0,
            "Low": 2.0,
            "Informational": 0.0
        }

        confidence_multipliers = {
            "High": 1.0,
            "Medium": 0.8,
            "Low": 0.6
        }

        base_score = base_scores.get(impact, 0.0)
        multiplier = confidence_multipliers.get(confidence, 0.8)

        return base_score * multiplier

class MythrilTool(BaseTool):
    """Integration with Mythril symbolic execution tool."""

    def __init__(self, mythril_path: str = "mythril"):
        super().__init__(
            name="Mythril",
            description="Symbolic execution tool for Ethereum smart contracts"
        )
        self.mythril_path = mythril_path

    def run_analysis(self, target: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Mythril analysis on target contract."""
        config = config or {}

        # Create temporary file for analysis
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(target if target.endswith('.sol') else self._create_temp_contract(target))
            temp_file = f.name

        try:
            # Prepare command
            cmd = [
                self.mythril_path,
                "analyze",
                temp_file,
                "--json",
                "--max-depth", str(config.get("max_depth", 10)),
                "--loop-bound", str(config.get("loop_bound", 3))
            ]

            if config.get("enable_iprof"):
                cmd.append("--enable-iprof")

            # Run Mythril
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.get("timeout", 600)
            )

            if result.returncode == 0:
                findings = self._parse_mythril_output(result.stdout)
                return {
                    "success": True,
                    "findings": findings,
                    "raw_output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr,
                    "raw_output": result.stdout
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Analysis timed out"
            }
        finally:
            # Clean up temporary file
            os.unlink(temp_file)

    def _create_temp_contract(self, contract_code: str) -> str:
        """Create temporary contract file from code string."""
        return f'''
pragma solidity ^0.8.0;

contract TempContract {{
    {contract_code}
}}
'''

    def _parse_mythril_output(self, output: str) -> List[Finding]:
        """Parse Mythril JSON output."""
        findings = []

        try:
            data = json.loads(output)

            for issue in data.get("issues", []):
                finding = Finding(
                    id=f"mythril_{issue.get('type', 'unknown')}_{hash(str(issue)) % 10000}",
                    type=issue.get("type", "unknown"),
                    severity=self._map_mythril_severity(issue.get("severity", "unknown")),
                    confidence="high",  # Mythril typically has high confidence
                    title=issue.get("title", "Unknown issue"),
                    description=issue.get("description", ""),
                    location={
                        "file": "contract.sol",
                        "line": issue.get("lineno", 0),
                        "column": 0
                    },
                    code_snippet=issue.get("code", ""),
                    impact=issue.get("severity", "unknown"),
                    recommendation="",  # Mythril doesn't provide recommendations
                    cvss_score=self._calculate_mythril_cvss(issue),
                    references=[],
                    metadata={
                        "tool": "mythril",
                        "raw_issue": issue
                    }
                )
                findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings

    def _map_mythril_severity(self, severity: str) -> Severity:
        """Map Mythril severity."""
        mapping = {
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW
        }
        return mapping.get(severity, Severity.INFO)

    def _calculate_mythril_cvss(self, issue: Dict) -> float:
        """Calculate CVSS score for Mythril issue."""
        severity = issue.get("severity", "Low")
        scores = {
            "High": 8.0,
            "Medium": 6.0,
            "Low": 3.0
        }
        return scores.get(severity, 0.0)

# Usage example
def main():
    # Initialize tools
    slither = SlitherTool()
    mythril = MythrilTool()

    # Sample contract
    contract_code = '''
pragma solidity ^0.8.0;

contract SimpleToken {
    mapping(address => uint) balances;

    function transfer(address to, uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[to] += amount;
        balances[msg.sender] -= amount;
    }
}
'''

    # Create temporary contract file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write(contract_code)
        contract_file = f.name

    try:
        print("🔍 Running Slither analysis...")
        slither_results = slither.run_analysis(contract_file)

        print("🔍 Running Mythril analysis...")
        mythril_results = mythril.run_analysis(contract_code)

        # Combine results
        all_findings = []
        all_findings.extend(slither_results.get("findings", []))
        all_findings.extend(mythril_results.get("findings", []))

        print(f"📊 Combined Analysis Results:")
        print(f"   Total Findings: {len(all_findings)}")

        for finding in all_findings:
            print(f"   🚨 {finding.severity.upper()}: {finding.title}")

    finally:
        os.unlink(contract_file)

if __name__ == "__main__":
    main()
```

---

## Configuration Examples

### Example 7: Advanced Configuration

```yaml
# advanced_audit_config.yaml
audit:
  # General settings
  name: "Advanced DeFi Protocol Audit"
  version: "2.0.0"
  auditor: "Web3 Security AI v0.1.0"

  # Target specification
  target:
    type: "protocol"  # contract, protocol, dapp
    path: "./contracts"
    include_patterns:
      - "**/*.sol"
    exclude_patterns:
      - "**/test/**"
      - "**/mock/**"

  # Analysis configuration
  analysis:
    depth: "comprehensive"  # basic, standard, comprehensive, deep
    parallel: true
    timeout: 1800  # 30 minutes
    max_workers: 4

    # Tool-specific configurations
    tools:
      slither:
        enabled: true
        config:
          exclude_dependencies: true
          detectors:
            - "reentrancy"
            - "unchecked-lowlevel-call"
            - "arbitrary-send"
          solc_version: "0.8.19"

      mythril:
        enabled: true
        config:
          max_depth: 12
          loop_bound: 3
          enable_iprof: true
          timeout: 600

      custom_ml:
        enabled: true
        config:
          model_path: "./models/vulnerability_classifier.pkl"
          confidence_threshold: 0.8
          feature_extraction: "advanced"

    # Agent configurations
    agents:
      orchestrator:
        max_concurrent_audits: 3
        retry_failed_agents: true
        agent_timeout: 300

      web3_audit:
        deep_analysis: true
        check_inheritance: true
        analyze_state_changes: true
        verify_access_controls: true

      ml_engine:
        models:
          - name: "vulnerability_classifier"
            type: "classification"
            threshold: 0.75
          - name: "risk_predictor"
            type: "regression"
            features: ["complexity", "external_calls", "state_changes"]

  # Reporting configuration
  reporting:
    formats: ["json", "pdf", "html"]
    include_source_code: true
    include_recommendations: true
    risk_threshold: "medium"  # low, medium, high, critical

    # PDF report settings
    pdf:
      template: "professional"
      include_charts: true
      include_code_snippets: true
      max_findings_per_page: 10

    # JSON report settings
    json:
      pretty_print: true
      include_metadata: true
      schema_version: "1.0"

  # Integration settings
  integrations:
    github:
      enabled: true
      repository: "org/protocol-repo"
      create_issues: true
      labels: ["security", "audit"]

    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channels:
        - "#security-audits"
        - "#dev-team"

    jira:
      enabled: true
      server: "company.atlassian.net"
      project: "SEC"
      issue_type: "Bug"

  # Security settings
  security:
    guardrails:
      enabled: true
      prompt_injection_protection: true
      dangerous_command_blocking: true

    encryption:
      enabled: true
      key_path: "./keys/audit_key.pem"

    audit_trail:
      enabled: true
      log_level: "INFO"
      retention_days: 365

  # Performance tuning
  performance:
    memory_limit: "4GB"
    cpu_limit: "2.0"  # 2 CPU cores
    disk_limit: "10GB"

    caching:
      enabled: true
      cache_dir: "./.audit_cache"
      max_cache_size: "1GB"
      ttl: 86400  # 24 hours

  # Environment settings
  environment:
    variables:
      SOLC_VERSION: "0.8.19"
      PYTHONPATH: "./src"
      AUDIT_ENV: "production"

    paths:
      solc: "/usr/local/bin/solc"
      python: "/usr/bin/python3.12"
      tools_dir: "./tools"
```

### Example 8: CI/CD Integration Config

```yaml
# ci_audit_config.yaml
ci:
  enabled: true
  fail_on_findings: true
  fail_threshold: "high"  # Fail if any high or critical findings

  # Pull request integration
  pull_request:
    comment: true
    require_review: true
    block_merge: false

  # Branch protection
  branches:
    main:
      require_audit: true
      max_critical_findings: 0
      max_high_findings: 2

    develop:
      require_audit: true
      max_critical_findings: 1
      max_high_findings: 5

  # Notification settings
  notifications:
    email:
      enabled: true
      recipients: ["security@company.com", "dev-team@company.com"]
      on_failure_only: false

    slack:
      enabled: true
      channel: "#security-audits"
      mention_groups: ["@security-team"]

# Tool configurations optimized for CI
tools:
  slither:
    timeout: 120  # Shorter timeout for CI
    config:
      exclude_dependencies: true
      detectors: ["reentrancy", "unchecked-lowlevel-call"]

  mythril:
    timeout: 180
    config:
      max_depth: 8  # Reduced for faster CI runs

# Reporting optimized for CI
reporting:
  formats: ["json", "junit"]  # JUnit for CI integration
  output_dir: "./audit-results"
  include_source_code: false  # Reduce output size
```

---

## Advanced Usage Patterns

### Example 9: Parallel Multi-Protocol Audit

```python
#!/usr/bin/env python3
"""
Advanced parallel multi-protocol auditing example.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from web3_security_ai.orchestrator import AuditOrchestrator
from web3_security_ai.agents import Web3AuditAgent, DeFiAuditAgent, NFTAuditAgent
import time

async def audit_multiple_protocols(protocols: List[Dict]) -> List[Dict]:
    """
    Audit multiple protocols in parallel.

    Args:
        protocols: List of protocol configurations

    Returns:
        List of audit results
    """

    # Create orchestrator with multiple agent types
    agents = [
        Web3AuditAgent(),
        DeFiAuditAgent(),
        NFTAuditAgent()
    ]

    orchestrator = AuditOrchestrator(agents)

    # Run audits in parallel using thread pool
    with ThreadPoolExecutor(max_workers=4) as executor:
        loop = asyncio.get_event_loop()

        # Create audit tasks
        audit_tasks = []
        for protocol in protocols:
            task = loop.run_in_executor(
                executor,
                orchestrator.run_full_audit,
                protocol
            )
            audit_tasks.append((protocol["name"], task))

        # Wait for all audits to complete
        results = []
        for protocol_name, task in audit_tasks:
            try:
                start_time = time.time()
                result = await task
                duration = time.time() - start_time

                results.append({
                    "protocol": protocol_name,
                    "success": True,
                    "result": result,
                    "duration": duration
                })

                print(f"✅ Completed audit for {protocol_name} in {duration:.1f}s")

            except Exception as e:
                results.append({
                    "protocol": protocol_name,
                    "success": False,
                    "error": str(e),
                    "duration": 0
                })

                print(f"❌ Failed audit for {protocol_name}: {str(e)}")

        return results

def main():
    # Define multiple protocols to audit
    protocols = [
        {
            "name": "Uniswap V3",
            "type": "defi",
            "contracts": ["contracts/uniswap/v3/core/*.sol"],
            "analysis_depth": "comprehensive",
            "check_flash_loans": True
        },
        {
            "name": "Compound Finance",
            "type": "defi",
            "contracts": ["contracts/compound/*.sol"],
            "analysis_depth": "comprehensive",
            "verify_interest_rate_model": True
        },
        {
            "name": "OpenSea Contracts",
            "type": "nft",
            "contracts": ["contracts/opensea/*.sol"],
            "analysis_depth": "standard",
            "check_royalty_implementation": True
        },
        {
            "name": "Custom Token",
            "type": "erc20",
            "contracts": ["contracts/token/*.sol"],
            "analysis_depth": "basic"
        }
    ]

    print("🚀 Starting parallel multi-protocol audit...")
    print(f"📊 Auditing {len(protocols)} protocols")
    print("=" * 60)

    # Run parallel audits
    start_time = time.time()
    results = asyncio.run(audit_multiple_protocols(protocols))
    total_time = time.time() - start_time

    # Summarize results
    successful = sum(1 for r in results if r["success"])
    total_findings = sum(
        len(r.get("result", {}).get("findings", []))
        for r in results if r["success"]
    )

    print("\n📈 Audit Summary:")
    print(f"   Total Protocols: {len(protocols)}")
    print(f"   Successful Audits: {successful}")
    print(f"   Failed Audits: {len(protocols) - successful}")
    print(f"   Total Findings: {total_findings}")
    print(".1f"    print(".2f"
    # Detailed results
    print("\n📋 Detailed Results:")
    for result in results:
        status = "✅" if result["success"] else "❌"
        findings = len(result.get("result", {}).get("findings", [])) if result["success"] else 0
        print(".1f"
if __name__ == "__main__":
    main()
```

### Example 10: Custom Reporting and Analytics

```python
#!/usr/bin/env python3
"""
Custom reporting and analytics example.
"""

import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Dict, Any
from web3_security_ai.models import Finding, Severity

class AuditAnalytics:
    """Custom analytics and reporting for audit results."""

    def __init__(self, audit_results: List[Dict]):
        self.audit_results = audit_results
        self.findings = self._extract_findings()

    def _extract_findings(self) -> List[Finding]:
        """Extract all findings from audit results."""
        all_findings = []
        for result in self.audit_results:
            if result.get("success") and "result" in result:
                findings = result["result"].get("findings", [])
                all_findings.extend(findings)
        return all_findings

    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive summary report."""
        return {
            "audit_summary": {
                "total_audits": len(self.audit_results),
                "successful_audits": sum(1 for r in self.audit_results if r.get("success")),
                "failed_audits": sum(1 for r in self.audit_results if not r.get("success")),
                "total_findings": len(self.findings)
            },
            "findings_by_severity": self._findings_by_severity(),
            "findings_by_type": self._findings_by_type(),
            "findings_by_contract": self._findings_by_contract(),
            "risk_assessment": self._calculate_risk_score(),
            "recommendations": self._generate_recommendations()
        }

    def _findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level."""
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] += 1
        return dict(severity_counts)

    def _findings_by_type(self) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        type_counts = Counter(
            finding.get("type", "unknown") for finding in self.findings
        )
        return dict(type_counts)

    def _findings_by_contract(self) -> Dict[str, int]:
        """Count findings by contract."""
        contract_counts = defaultdict(int)
        for finding in self.findings:
            location = finding.get("location", {})
            contract = location.get("file", "unknown")
            contract_counts[contract] += 1
        return dict(contract_counts)

    def _calculate_risk_score(self) -> Dict[str, Any]:
        """Calculate overall risk score."""
        if not self.findings:
            return {"score": 0.0, "level": "None", "description": "No findings detected"}

        # Weight findings by severity
        weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.1
        }

        total_score = 0.0
        max_possible_score = len(self.findings) * 10.0

        for finding in self.findings:
            severity = finding.get("severity", "info")
            weight = weights.get(severity, 0.1)
            total_score += weight

        # Normalize to 0-10 scale
        normalized_score = min(10.0, (total_score / max_possible_score) * 10.0)

        # Determine risk level
        if normalized_score >= 8.0:
            level = "Critical"
        elif normalized_score >= 6.0:
            level = "High"
        elif normalized_score >= 4.0:
            level = "Medium"
        elif normalized_score >= 2.0:
            level = "Low"
        else:
            level =