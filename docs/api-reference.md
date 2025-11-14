# API Reference Documentation

This document provides comprehensive API documentation for all agent interfaces and system components of the Web3 Security Auditing AI System.

## Table of Contents

- [Orchestrator Agent API](#orchestrator-agent-api)
- [Web3 Audit Agent API](#web3-audit-agent-api)
- [AI/ML Engine API](#aiml-engine-api)
- [Static Analysis Adapter API](#static-analysis-adapter-api)
- [Traditional Security Agent API](#traditional-security-agent-api)
- [Core System APIs](#core-system-apis)
- [Data Models](#data-models)
- [Error Handling](#error-handling)

---

## Orchestrator Agent API

### AuditOrchestrator

The main coordination class for running comprehensive audits.

#### Constructor

```python
AuditOrchestrator(
    agents: List[BaseAuditAgent],
    config: Optional[OrchestratorConfig] = None
)
```

**Parameters:**
- `agents`: List of audit agents to coordinate
- `config`: Optional orchestrator configuration

#### Methods

##### run_full_audit(config: dict) -> AuditReport

Execute end-to-end audit workflow.

**Parameters:**
- `config` (dict): Audit configuration including:
  - `target`: Contract path, code, or repository URL
  - `analysis_type`: "basic", "comprehensive", or "deep"
  - `tools`: List of tools to use
  - `timeout`: Analysis timeout in seconds
  - `parallel`: Enable parallel processing

**Returns:**
- `AuditReport`: Complete audit report with findings

**Raises:**
- `AuditTimeoutError`: When analysis exceeds timeout
- `AgentCommunicationError`: When agent coordination fails
- `ConfigurationError`: When config is invalid

**Example:**
```python
orchestrator = AuditOrchestrator([web3_agent, ml_agent])
config = {
    "target": "contracts/Token.sol",
    "analysis_type": "comprehensive",
    "tools": ["slither", "mythril"],
    "timeout": 300
}
report = orchestrator.run_full_audit(config)
```

##### run_parallel_audit(targets: List[str]) -> List[AuditReport]

Run parallel audits on multiple targets.

**Parameters:**
- `targets` (List[str]): List of targets to audit

**Returns:**
- `List[AuditReport]`: List of audit reports

##### get_status() -> dict

Get current audit status and progress.

**Returns:**
- `dict`: Status information including:
  - `active_audits`: Number of running audits
  - `completed_audits`: Number of completed audits
  - `failed_audits`: Number of failed audits
  - `progress`: Overall progress percentage

##### pause_audit(audit_id: str) -> bool

Pause a running audit.

**Parameters:**
- `audit_id` (str): Unique audit identifier

**Returns:**
- `bool`: True if paused successfully

##### resume_audit(audit_id: str) -> bool

Resume a paused audit.

**Parameters:**
- `audit_id` (str): Unique audit identifier

**Returns:**
- `bool`: True if resumed successfully

##### cancel_audit(audit_id: str) -> bool

Cancel a running audit.

**Parameters:**
- `audit_id` (str): Unique audit identifier

**Returns:**
- `bool`: True if cancelled successfully

---

## Web3 Audit Agent API

### Web3AuditAgent

Specialized agent for blockchain and smart contract analysis.

#### Constructor

```python
Web3AuditAgent(
    config: Optional[Web3AgentConfig] = None,
    tools: Optional[List[BaseTool]] = None
)
```

#### Methods

##### analyze_contract(contract_code: str, config: dict = None) -> List[Finding]

Analyze smart contract code for vulnerabilities.

**Parameters:**
- `contract_code` (str): Solidity contract source code
- `config` (dict): Analysis configuration

**Returns:**
- `List[Finding]`: List of security findings

**Example:**
```python
agent = Web3AuditAgent()
findings = agent.analyze_contract("""
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint) balances;
    function transfer(address to, uint amount) public {
        balances[msg.sender] -= amount; // Bug: no underflow check
        balances[to] += amount;
    }
}
""")
```

##### analyze_protocol(protocol_config: dict) -> ProtocolReport

Analyze complete blockchain protocol.

**Parameters:**
- `protocol_config` (dict): Protocol configuration including:
  - `contracts`: List of contract paths
  - `networks`: Target networks
  - `analysis_depth`: Analysis depth level

**Returns:**
- `ProtocolReport`: Comprehensive protocol analysis report

##### check_compliance(contract: str, standards: List[str]) -> ComplianceReport

Check compliance with security standards.

**Parameters:**
- `contract` (str): Contract source code
- `standards` (List[str]): Standards to check (e.g., ["ERC-20", "SWC"])

**Returns:**
- `ComplianceReport`: Compliance assessment results

##### detect_patterns(contract: str) -> List[PatternMatch]

Detect known vulnerability patterns.

**Parameters:**
- `contract` (str): Contract source code

**Returns:**
- `List[PatternMatch]`: Matched vulnerability patterns

---

## AI/ML Engine API

### MLSecurityAnalyzer

Machine learning-powered vulnerability detection and classification.

#### Constructor

```python
MLSecurityAnalyzer(
    model_path: Optional[str] = None,
    config: Optional[MLConfig] = None
)
```

#### Methods

##### classify_vulnerability(code_pattern: str, context: dict = None) -> dict

Classify code pattern as vulnerability type.

**Parameters:**
- `code_pattern` (str): Code snippet to analyze
- `context` (dict): Additional context information

**Returns:**
- `dict`: Classification results including:
  - `vulnerability_type`: Predicted vulnerability type
  - `severity`: Predicted severity level
  - `confidence`: Classification confidence score
  - `explanation`: AI-generated explanation

**Example:**
```python
analyzer = MLSecurityAnalyzer()
result = analyzer.classify_vulnerability("""
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}
""")
# Returns: {'vulnerability_type': 'reentrancy', 'severity': 'high', 'confidence': 0.92}
```

##### predict_risk_score(contract_features: dict) -> float

Predict CVSS risk score for contract.

**Parameters:**
- `contract_features` (dict): Extracted contract features

**Returns:**
- `float`: Predicted CVSS score (0.0-10.0)

##### detect_anomalies(transaction_data: List[dict]) -> List[Anomaly]

Detect anomalous transaction patterns.

**Parameters:**
- `transaction_data` (List[dict]): Transaction data to analyze

**Returns:**
- `List[Anomaly]`: Detected anomalies with details

##### train_model(training_data: List[dict], validation_data: List[dict]) -> TrainingResult

Train ML model on new data.

**Parameters:**
- `training_data` (List[dict]): Training dataset
- `validation_data` (List[dict]): Validation dataset

**Returns:**
- `TrainingResult`: Training metrics and model performance

##### evaluate_model(test_data: List[dict]) -> EvaluationMetrics

Evaluate model performance.

**Parameters:**
- `test_data` (List[dict]): Test dataset

**Returns:**
- `EvaluationMetrics`: Performance metrics (accuracy, precision, recall, F1)

---

## Static Analysis Adapter API

### StaticAnalysisAdapter

Integration layer for static analysis tools.

#### Constructor

```python
StaticAnalysisAdapter(
    tool_configs: Optional[Dict[str, dict]] = None
)
```

#### Methods

##### integrate_tool(tool_name: str, config: dict) -> bool

Integrate new static analysis tool.

**Parameters:**
- `tool_name` (str): Name of the tool (e.g., "slither", "mythril")
- `config` (dict): Tool-specific configuration

**Returns:**
- `bool`: True if integration successful

**Supported Tools:**
- `slither`: Smart contract static analyzer
- `mythril`: Symbolic execution tool
- `oyente`: Transaction analysis tool
- `securify`: Security analysis tool

**Example:**
```python
adapter = StaticAnalysisAdapter()
success = adapter.integrate_tool("slither", {
    "version": "0.10.0",
    "solc_version": "0.8.19",
    "exclude_dependencies": True
})
```

##### run_analysis(target: str, tools: List[str], config: dict = None) -> AnalysisResults

Run specified tools on target.

**Parameters:**
- `target` (str): Target contract or directory path
- `tools` (List[str]): List of tools to run
- `config` (dict): Analysis configuration

**Returns:**
- `AnalysisResults`: Combined results from all tools

##### parse_results(raw_output: str, tool: str) -> List[Finding]

Parse tool output into standardized findings.

**Parameters:**
- `raw_output` (str): Raw tool output
- `tool` (str): Tool name

**Returns:**
- `List[Finding]`: Standardized security findings

##### get_supported_tools() -> List[str]

Get list of supported tools.

**Returns:**
- `List[str]`: Supported tool names

##### validate_tool_config(tool: str, config: dict) -> ValidationResult

Validate tool configuration.

**Parameters:**
- `tool` (str): Tool name
- `config` (dict): Configuration to validate

**Returns:**
- `ValidationResult`: Validation results with errors/warnings

---

## Traditional Security Agent API

### TraditionalSecurityAgent

Conventional security assessment agent.

#### Constructor

```python
TraditionalSecurityAgent(
    config: Optional[SecurityConfig] = None
)
```

#### Methods

##### assess_network_security(config: dict) -> NetworkReport

Assess network-level security.

**Parameters:**
- `config` (dict): Network assessment configuration including:
  - `target_network`: Network to assess
  - `scan_ports`: Port range to scan
  - `vulnerability_checks`: Enabled vulnerability checks

**Returns:**
- `NetworkReport`: Network security assessment results

##### check_access_controls(system: str, config: dict = None) -> AccessReport

Validate access control mechanisms.

**Parameters:**
- `system` (str): System or contract to analyze
- `config` (dict): Access control check configuration

**Returns:**
- `AccessReport`: Access control assessment results

##### audit_configuration(config_files: List[str]) -> ConfigReport

Audit system configuration security.

**Parameters:**
- `config_files` (List[str]): Configuration files to audit

**Returns:**
- `ConfigReport`: Configuration security assessment

##### perform_compliance_check(system: str, standards: List[str]) -> ComplianceReport

Perform compliance checks against standards.

**Parameters:**
- `system` (str): System to check
- `standards` (List[str]): Compliance standards (e.g., ["NIST", "ISO27001"])

**Returns:**
- `ComplianceReport`: Compliance assessment results

##### generate_security_recommendations(findings: List[Finding]) -> List[Recommendation]

Generate security recommendations from findings.

**Parameters:**
- `findings` (List[Finding]): Security findings

**Returns:**
- `List[Recommendation]`: Actionable security recommendations

---

## Core System APIs

### AuditAPI

REST API interface for audit operations.

#### Endpoints

##### POST /api/v1/audit/submit

Submit audit request.

**Request Body:**
```json
{
  "target": "contract.sol",
  "analysis_type": "comprehensive",
  "tools": ["slither", "mythril"],
  "config": {
    "timeout": 300,
    "parallel": true
  }
}
```

**Response:**
```json
{
  "audit_id": "audit-12345",
  "status": "queued",
  "estimated_time": 180
}
```

##### GET /api/v1/audit/{audit_id}/status

Get audit status.

**Response:**
```json
{
  "audit_id": "audit-12345",
  "status": "running",
  "progress": 65,
  "current_step": "Static Analysis",
  "start_time": "2024-11-05T06:26:13Z",
  "estimated_completion": "2024-11-05T06:31:13Z"
}
```

##### GET /api/v1/audit/{audit_id}/results

Get audit results.

**Response:**
```json
{
  "audit_id": "audit-12345",
  "status": "completed",
  "summary": {
    "total_findings": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "findings": [...],
  "report_url": "/api/v1/reports/audit-12345.pdf"
}
```

##### POST /api/v1/tools/register

Register custom tool.

**Request Body:**
```json
{
  "name": "custom_scanner",
  "type": "static_analysis",
  "config": {
    "command": "custom-scan",
    "args": ["--target", "{target}"]
  }
}
```

### CLI API

Command-line interface for audit operations.

#### Commands

##### web3-audit audit [target]

Run audit on target.

```bash
# Basic audit
web3-audit audit contract.sol

# Comprehensive audit with specific tools
web3-audit audit contracts/ --comprehensive --tools slither,mythril

# Audit with custom config
web3-audit audit contract.sol --config audit_config.yaml
```

##### web3-audit status [audit_id]

Check audit status.

```bash
web3-audit status audit-12345
```

##### web3-audit report [audit_id]

Generate audit report.

```bash
# Generate PDF report
web3-audit report audit-12345 --format pdf

# Generate multiple formats
web3-audit report audit-12345 --format json,pdf,html
```

##### web3-audit tools list

List available tools.

```bash
web3-audit tools list
```

##### web3-audit config validate [config_file]

Validate configuration file.

```bash
web3-audit config validate audit_config.yaml
```

---

## Data Models

### Finding

Security finding data model.

```python
@dataclass
class Finding:
    id: str
    type: str  # e.g., "reentrancy", "overflow"
    severity: str  # "critical", "high", "medium", "low", "info"
    confidence: str  # "high", "medium", "low"
    title: str
    description: str
    location: Location
    code_snippet: str
    impact: str
    recommendation: str
    cvss_score: float
    references: List[str]
    metadata: Dict[str, Any]
```

### Location

Code location information.

```python
@dataclass
class Location:
    file: str
    line: int
    column: int
    function: Optional[str] = None
    contract: Optional[str] = None
```

### AuditReport

Complete audit report.

```python
@dataclass
class AuditReport:
    audit_id: str
    timestamp: datetime
    target: str
    auditor_version: str
    summary: ReportSummary
    findings: List[Finding]
    recommendations: List[Recommendation]
    compliance: ComplianceResults
    metadata: Dict[str, Any]
```

### ReportSummary

Audit summary statistics.

```python
@dataclass
class ReportSummary:
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: float
    analysis_time: float
```

---

## Error Handling

### Exception Hierarchy

```
AuditError
├── ConfigurationError
├── ValidationError
├── TimeoutError
├── AgentError
│   ├── AgentCommunicationError
│   ├── AgentTimeoutError
│   └── AgentConfigurationError
├── ToolError
│   ├── ToolNotFoundError
│   ├── ToolExecutionError
│   └── ToolTimeoutError
├── AnalysisError
│   ├── AnalysisTimeoutError
│   ├── AnalysisFailureError
│   └── AnalysisConfigurationError
└── ReportError
    ├── ReportGenerationError
    └── ReportExportError
```

### Error Response Format

```json
{
  "error": {
    "type": "ToolExecutionError",
    "message": "Slither analysis failed",
    "details": "Command execution timeout",
    "audit_id": "audit-12345",
    "timestamp": "2024-11-05T06:26:13Z",
    "traceback": "..."
  }
}
```

### Error Handling Best Practices

```python
try:
    report = orchestrator.run_full_audit(config)
except TimeoutError as e:
    logger.warning(f"Audit timed out: {e}")
    # Implement retry logic or partial results
except AgentCommunicationError as e:
    logger.error(f"Agent communication failed: {e}")
    # Attempt to restart failed agents
except ConfigurationError as e:
    logger.error(f"Invalid configuration: {e}")
    # Validate and prompt for corrected config
finally:
    # Cleanup resources
    orchestrator.cleanup()
```

### Retry Mechanisms

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def run_audit_with_retry(orchestrator, config):
    return orchestrator.run_full_audit(config)
```

---

## Authentication and Authorization

### API Authentication

The system supports multiple authentication methods:

#### JWT Token Authentication
```python
import jwt
from datetime import datetime, timedelta

def generate_token(user_id: str, secret: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, secret, algorithm='HS256')
```

#### API Key Authentication
```python
# Header: Authorization: Bearer <api_key>
headers = {
    'Authorization': f'Bearer {api_key}',
    'Content-Type': 'application/json'
}
```

### Role-Based Access Control

```python
class UserRole:
    ADMIN = "admin"      # Full system access
    AUDITOR = "auditor"  # Can run audits and view reports
    VIEWER = "viewer"    # Can only view reports
    API_USER = "api"     # API-only access
```

### Rate Limiting

```python
# Rate limits per user role
RATE_LIMITS = {
    UserRole.ADMIN: "1000/hour",
    UserRole.AUDITOR: "100/hour",
    UserRole.VIEWER: "50/hour",
    UserRole.API_USER: "500/hour"
}
```

---

## Webhooks and Callbacks

### Webhook Configuration

```python
from web3_security_ai.webhooks import WebhookManager

webhook_manager = WebhookManager()

# Register webhook for audit completion
webhook_manager.register_webhook(
    event="audit_completed",
    url="https://example.com/webhook/audit-complete",
    secret="webhook_secret"
)
```

### Webhook Payload

```json
{
  "event": "audit_completed",
  "audit_id": "audit-12345",
  "status": "completed",
  "timestamp": "2024-11-05T06:26:13Z",
  "summary": {
    "total_findings": 5,
    "critical": 1,
    "high": 2
  },
  "report_url": "https://api.web3-security-ai.com/reports/audit-12345.pdf",
  "signature": "sha256=..."
}
```

### Webhook Security

```python
import hmac
import hashlib

def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    expected_signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, f"sha256={expected_signature}")
```

---

This API reference provides comprehensive documentation for integrating with and extending the Web3 Security Auditing AI System. For additional examples and tutorials, see the [examples](../examples/) directory.