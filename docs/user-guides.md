# User Guides

This section provides comprehensive guides for different use cases of the Web3 Security Auditing AI System.

## Basic Smart Contract Auditing

### Getting Started

#### Prerequisites
- Basic understanding of Solidity
- Smart contract source code
- Compiled contract artifacts (optional but recommended)

#### Quick Audit Setup

1. **Prepare Your Contract**
   ```bash
   # Ensure your contract compiles without errors
   solc --version
   solc --bin --abi YourContract.sol
   ```

2. **Basic Audit Command**
   ```bash
   # Audit a single contract file
   web3-audit audit contracts/Token.sol --output audit_report.json

   # Audit with specific tools
   web3-audit audit contracts/Token.sol --tools slither --format pdf
   ```

### Understanding Audit Results

#### Severity Levels
- **Critical**: Immediate security risk requiring immediate action
- **High**: Significant security vulnerability
- **Medium**: Moderate security concern
- **Low**: Minor issue or best practice violation
- **Info**: Informational finding

#### Common Vulnerability Types

##### Reentrancy
```solidity
// VULNERABLE CODE
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount; // Update after external call
}

// SECURE CODE
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // Update before external call
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
```

##### Integer Overflow/Underflow
```solidity
// VULNERABLE CODE (Solidity < 0.8.0)
function transfer(address to, uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[to] += amount; // Can overflow
    balances[msg.sender] -= amount;
}

// SECURE CODE
function transfer(address to, uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[to] = balances[to] + amount; // Use SafeMath or Solidity >= 0.8.0
    balances[msg.sender] = balances[msg.sender] - amount;
}
```

##### Access Control Issues
```solidity
// VULNERABLE CODE
function emergencyWithdraw() public {
    // Anyone can call this!
    payable(owner).transfer(address(this).balance);
}

// SECURE CODE
function emergencyWithdraw() public onlyOwner {
    payable(owner).transfer(address(this).balance);
}
```

### Step-by-Step Audit Process

1. **Code Review Preparation**
   ```bash
   # Create audit workspace
   mkdir audit_workspace
   cd audit_workspace

   # Copy contract files
   cp ../contracts/*.sol ./

   # Initialize audit configuration
   web3-audit init
   ```

2. **Automated Analysis**
   ```bash
   # Run comprehensive audit
   web3-audit audit . --comprehensive --parallel

   # Check progress
   web3-audit status
   ```

3. **Manual Review**
   ```bash
   # Open interactive review mode
   web3-audit review audit_report.json

   # Focus on critical findings
   web3-audit review --severity critical,high
   ```

4. **Generate Final Report**
   ```bash
   # Generate detailed PDF report
   web3-audit report --format pdf --include-code

   # Export to multiple formats
   web3-audit report --format json,pdf,html
   ```

## Advanced Blockchain Protocol Analysis

### DeFi Protocol Assessment

#### Protocol Scope Definition
```yaml
# defi_protocol_config.yaml
protocol:
  name: "Uniswap V3 Clone"
  version: "1.0.0"
  type: "AMM"

contracts:
  core:
    - "contracts/core/UniswapV3Factory.sol"
    - "contracts/core/UniswapV3Pool.sol"
  periphery:
    - "contracts/periphery/SwapRouter.sol"
    - "contracts/periphery/NonfungiblePositionManager.sol"

networks:
  - ethereum
  - polygon
  - arbitrum

analysis_depth: comprehensive
```

#### Running DeFi Audit
```python
from web3_security_ai.orchestrator import AuditOrchestrator
from web3_security_ai.agents import DeFiAuditAgent, LiquidityAnalysisAgent

# Initialize specialized agents
agents = [
    DeFiAuditAgent(),
    LiquidityAnalysisAgent(),
    FlashLoanDetector()
]

# Create orchestrator
orchestrator = AuditOrchestrator(agents)

# Run protocol audit
config = load_config('defi_protocol_config.yaml')
report = orchestrator.run_protocol_audit(config)

# Generate comprehensive report
report.generate_pdf('defi_audit_report.pdf')
```

#### DeFi-Specific Checks

##### Impermanent Loss Protection
```solidity
// Check for IL protection mechanisms
function checkImpermanentLossProtection() {
    // Analyze liquidity provision logic
    // Check for minimum liquidity thresholds
    // Validate price impact calculations
}
```

##### Flash Loan Attack Vectors
```solidity
// Vulnerable lending pool
function flashLoan(address borrower, uint amount) external {
    uint balanceBefore = token.balanceOf(address(this));
    token.transfer(borrower, amount);

    // Borrower can execute arbitrary logic here
    // No validation of loan repayment

    uint balanceAfter = token.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Loan not repaid");
}
```

##### Oracle Manipulation Prevention
```solidity
// Secure price oracle usage
function getSecurePrice() public view returns (uint) {
    uint[] memory prices = new uint[](3);
    prices[0] = chainlinkOracle.getPrice();
    prices[1] = uniswapTWAP.getPrice();
    prices[2] = customOracle.getPrice();

    // Use median price to prevent manipulation
    return median(prices);
}
```

### Cross-Chain Bridge Security

#### Bridge Audit Configuration
```yaml
bridge_audit:
  name: "Cross-Chain Bridge"
  components:
    source_chain:
      contracts:
        - "contracts/bridge/SourceBridge.sol"
      chain_id: 1  # Ethereum
    destination_chain:
      contracts:
        - "contracts/bridge/DestinationBridge.sol"
      chain_id: 137  # Polygon

  security_checks:
    - message_verification
    - replay_attack_protection
    - validator_consensus
    - emergency_pause_mechanism
```

#### Bridge Security Analysis
```python
from web3_security_ai.agents import BridgeSecurityAgent

bridge_agent = BridgeSecurityAgent()

# Analyze bridge contracts
findings = bridge_agent.analyze_bridge_security(
    source_contract="contracts/bridge/SourceBridge.sol",
    destination_contract="contracts/bridge/DestinationBridge.sol",
    validator_set=validator_addresses
)

# Check for common bridge vulnerabilities
bridge_agent.check_message_passing_integrity()
bridge_agent.verify_validator_consensus()
bridge_agent.test_emergency_mechanisms()
```

### NFT Marketplace Security

#### NFT Contract Audit
```python
from web3_security_ai.agents import NFTAuditAgent

nft_agent = NFTAuditAgent()

# Analyze NFT contract
audit_results = nft_agent.analyze_nft_contract(
    contract_path="contracts/NFT.sol",
    marketplace_integration=True
)

# Check for NFT-specific vulnerabilities
nft_agent.verify_ownership_transfer()
nft_agent.check_royalty_implementation()
nft_agent.validate_metadata_security()
```

## Bug Bounty Workflow

### Setting Up Bug Bounty Environment

1. **Target Scoping**
   ```python
   from web3_security_ai.bugbounty import BugBountyScope

   scope = BugBountyScope(
       in_scope=[
           "*.target.com",
           "app.target.com/contracts/*",
           "target.com/api/v1/*"
       ],
       out_of_scope=[
           "*.admin.target.com",
           "target.com/admin/*"
       ],
       rewards={
           "critical": 10000,
           "high": 5000,
           "medium": 2000,
           "low": 500
       }
   )
   ```

2. **Reconnaissance Phase**
   ```python
   from web3_security_ai.agents import ReconAgent

   recon = ReconAgent()
   targets = recon.discover_endpoints(scope)
   contracts = recon.find_smart_contracts(targets)
   apis = recon.enumerate_apis(targets)
   ```

3. **Automated Vulnerability Scanning**
   ```python
   from web3_security_ai.orchestrator import BugBountyOrchestrator

   bounty_orchestrator = BugBountyOrchestrator(scope)
   findings = bounty_orchestrator.run_automated_scan(targets)

   # Prioritize findings by bounty value
   prioritized = bounty_orchestrator.prioritize_by_reward(findings)
   ```

4. **Manual Testing Workflow**
   ```python
   from web3_security_ai.bugbounty import ManualTestingWorkflow

   workflow = ManualTestingWorkflow(scope)

   # Create testing checklist
   checklist = workflow.generate_checklist(targets)

   # Track testing progress
   workflow.update_progress(test_case_id, status="completed", finding=finding)

   # Generate bounty report
   report = workflow.generate_bounty_report()
   ```

### Bug Bounty Best Practices

#### Responsible Disclosure
```python
from web3_security_ai.bugbounty import ResponsibleDisclosure

disclosure = ResponsibleDisclosure(
    program="Target Bug Bounty",
    contact="security@target.com"
)

# Report finding securely
report_id = disclosure.submit_finding(
    title="Critical Reentrancy Vulnerability",
    severity="critical",
    description="Detailed vulnerability description",
    proof_of_concept="Exploit code and steps",
    impact="Potential loss of all contract funds"
)

# Follow up on disclosure
status = disclosure.check_status(report_id)
```

#### Finding Documentation
```python
from web3_security_ai.bugbounty import FindingDocumentation

doc = FindingDocumentation()

# Document comprehensive finding
finding = doc.create_finding(
    title="Access Control Bypass",
    severity="high",
    category="Authorization",
    affected_component="Admin Panel",
    description="""
    The admin panel lacks proper authorization checks,
    allowing any authenticated user to modify system settings.
    """,
    steps_to_reproduce=[
        "1. Login as regular user",
        "2. Navigate to /admin/settings",
        "3. Modify system configuration",
        "4. Changes are applied without authorization"
    ],
    impact="Complete system compromise possible",
    remediation="Implement proper RBAC checks"
)

# Generate bounty submission
submission = doc.generate_submission(finding, scope)
```

## Tool Integration Guide

### Integrating Custom Security Tools

#### Creating a Custom Tool
```python
from web3_security_ai.tools import BaseSecurityTool, ToolResult
from typing import List, Dict, Any

class CustomSecurityTool(BaseSecurityTool):
    def __init__(self):
        super().__init__(
            name="Custom Security Scanner",
            description="Specialized security analysis tool",
            version="1.0.0"
        )

    def analyze(self, target: str, config: Dict[str, Any] = None) -> ToolResult:
        """
        Perform custom security analysis on target.

        Args:
            target: File path or contract address to analyze
            config: Tool-specific configuration

        Returns:
            ToolResult with findings
        """
        findings = []

        try:
            # Your custom analysis logic here
            if self.detect_vulnerability(target):
                findings.append({
                    "type": "custom_vulnerability",
                    "severity": "high",
                    "description": "Custom vulnerability detected",
                    "location": target,
                    "confidence": 0.9
                })

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                findings=[]
            )

        return ToolResult(
            success=True,
            findings=findings,
            metadata={"scan_time": 10.5}
        )

    def detect_vulnerability(self, target: str) -> bool:
        """Custom vulnerability detection logic."""
        # Implement your detection algorithm
        return False
```

#### Registering Custom Tools
```python
from web3_security_ai.tool_registry import ToolRegistry

# Initialize registry
registry = ToolRegistry()

# Register custom tool
custom_tool = CustomSecurityTool()
registry.register_tool(custom_tool)

# Use in audit
from web3_security_ai.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator()
orchestrator.add_tool(custom_tool)

# Run audit with custom tool
results = orchestrator.run_audit("contract.sol", tools=["custom_security_scanner"])
```

### Integrating with CI/CD Pipelines

#### GitHub Actions Integration
```yaml
# .github/workflows/security-audit.yml
name: Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install Dependencies
      run: |
        pip install web3-security-ai

    - name: Run Security Audit
      run: |
        web3-audit audit contracts/ --output security_report.json --ci

    - name: Upload Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security_report.json

    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('security_report.json', 'utf8'));

          const comment = `## 🔒 Security Audit Results

          **Findings:** ${report.summary.total_findings}
          **Critical:** ${report.summary.critical}
          **High:** ${report.summary.high}

          [View Full Report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})`;

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

#### Jenkins Pipeline Integration
```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Security Audit') {
            steps {
                script {
                    // Install web3-security-ai
                    sh 'pip install web3-security-ai'

                    // Run audit
                    sh 'web3-audit audit contracts/ --output security_report.json --ci'

                    // Parse results
                    def report = readJSON file: 'security_report.json'

                    // Fail build on critical findings
                    if (report.summary.critical > 0) {
                        error("Critical security findings detected: ${report.summary.critical}")
                    }

                    // Archive report
                    archiveArtifacts artifacts: 'security_report.json', fingerprint: true
                }
            }
        }
    }

    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security_report.html',
                reportName: 'Security Audit Report'
            ])
        }
    }
}
```

### API Integration

#### REST API Integration
```python
import requests
from web3_security_ai.api import AuditAPI

# Initialize API client
api = AuditAPI(base_url="https://api.web3-security-ai.com")

# Submit audit request
response = api.submit_audit({
    "contract_code": contract_source,
    "analysis_type": "comprehensive",
    "tools": ["slither", "mythril"]
})

audit_id = response["audit_id"]

# Check status
status = api.get_audit_status(audit_id)

# Get results when complete
if status["status"] == "completed":
    results = api.get_audit_results(audit_id)
    print(f"Audit completed with {len(results['findings'])} findings")
```

#### Webhook Integration
```python
from flask import Flask, request
from web3_security_ai.api import WebhookHandler

app = Flask(__name__)
webhook_handler = WebhookHandler()

@app.route('/webhook/audit-complete', methods=['POST'])
def audit_webhook():
    data = request.get_json()

    # Process audit completion
    audit_id = data['audit_id']
    status = data['status']

    if status == 'completed':
        results = webhook_handler.get_results(audit_id)

        # Send notification, update dashboard, etc.
        notify_team(results)
        update_security_dashboard(results)

    return {'status': 'processed'}

if __name__ == '__main__':
    app.run(port=5000)
```

### Advanced Integration Patterns

#### Custom Agent Development
```python
from web3_security_ai.sdk import BaseAuditAgent, AgentConfig
from web3_security_ai.tools import ToolRegistry

class AdvancedSecurityAgent(BaseAuditAgent):
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.tool_registry = ToolRegistry()
        self.load_specialized_tools()

    def load_specialized_tools(self):
        """Load domain-specific security tools."""
        self.tool_registry.register_tool(AdvancedStaticAnalyzer())
        self.tool_registry.register_tool(MachineLearningDetector())
        self.tool_registry.register_tool(BlockchainSpecificChecker())

    def analyze_target(self, target: str) -> AuditReport:
        """Perform comprehensive analysis."""
        # Phase 1: Static Analysis
        static_results = self.run_static_analysis(target)

        # Phase 2: ML-based Detection
        ml_findings = self.run_ml_analysis(static_results)

        # Phase 3: Blockchain-specific Checks
        blockchain_findings = self.run_blockchain_checks(target)

        # Phase 4: Correlation and Risk Assessment
        correlated_findings = self.correlate_findings(
            static_results, ml_findings, blockchain_findings
        )

        return self.generate_report(correlated_findings)

    def correlate_findings(self, *finding_sets) -> List[CorrelatedFinding]:
        """Correlate findings from different analysis phases."""
        # Implement correlation logic
        pass
```

#### Plugin Architecture
```python
from web3_security_ai.plugins import PluginManager, BasePlugin

class CustomAuditPlugin(BasePlugin):
    name = "custom_audit_plugin"
    version = "1.0.0"
    description = "Custom security audit extensions"

    def initialize(self, plugin_manager: PluginManager):
        """Initialize plugin."""
        self.register_tools()
        self.register_agents()
        self.register_hooks()

    def register_tools(self):
        """Register custom tools."""
        self.plugin_manager.register_tool(CustomSecurityTool())

    def register_agents(self):
        """Register custom agents."""
        self.plugin_manager.register_agent(CustomAuditAgent())

    def register_hooks(self):
        """Register event hooks."""
        self.plugin_manager.register_hook(
            'audit_started',
            self.on_audit_started
        )

    def on_audit_started(self, audit_context):
        """Hook called when audit starts."""
        self.logger.info(f"Custom plugin: Audit started for {audit_context.target}")
```

This comprehensive user guide covers the main use cases and provides practical examples for getting started with the Web3 Security Auditing AI System.