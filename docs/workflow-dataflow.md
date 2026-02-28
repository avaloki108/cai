# Workflow and Data Flow Documentation

This document provides comprehensive documentation of the audit workflow, data formats, agent communication protocols, and report generation processes in CAI's Web3 security auditing flow.

> **Note:** All audit workflows run through the CAI-native `EliteWeb3Pipeline`
> (`src/cai/web3/pipeline.py`). The `web3_security_ai` package is a backward-
> compatibility adapter that delegates to this pipeline.

## Table of Contents

- [End-to-End Audit Process](#end-to-end-audit-process)
- [Data Formats and Schemas](#data-formats-and-schemas)
- [Agent Communication Protocols](#agent-communication-protocols)
- [Report Generation Process](#report-generation-process)
- [State Management](#state-management)
- [Error Handling and Recovery](#error-handling-and-recovery)
- [Performance Optimization](#performance-optimization)

---

## End-to-End Audit Process

### High-Level Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Input         │    │   Analysis      │    │   Processing    │    │   Output        │
│   Reception     │───▶│   Preparation   │───▶│   & Results     │───▶│   Generation    │
│                 │    │                 │    │   Aggregation    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
   │ Contract    │         │ Agent       │         │ Result      │         │ Report      │
   │ Validation  │         │ Coordination│         │ Correlation │         │ Generation  │
   └─────────────┘         └─────────────┘         └─────────────┘         └─────────────┘
```

### Detailed Process Flow

#### Phase 1: Input Reception and Validation

1. **Input Parsing**
   - Accept various input formats (files, URLs, code strings)
   - Validate input format and accessibility
   - Extract metadata (Solidity version, imports, dependencies)

2. **Target Analysis**
   - Build contract dependency graph
   - Identify entry points and external interfaces
   - Determine analysis scope and boundaries

3. **Configuration Processing**
   - Load user configuration and defaults
   - Validate configuration parameters
   - Set up analysis environment

#### Phase 2: Analysis Preparation

1. **Agent Initialization**
   - Load and configure audit agents
   - Initialize static analysis tools
   - Set up ML models and preprocessing

2. **Task Distribution**
   - Break down audit into parallelizable tasks
   - Assign tasks to appropriate agents
   - Set up inter-agent communication channels

3. **Resource Allocation**
   - Allocate computational resources
   - Set up temporary workspaces
   - Initialize monitoring and logging

#### Phase 3: Parallel Analysis Execution

1. **Static Analysis**
   - Run Slither, Mythril, and other static analyzers
   - Parse and normalize tool outputs
   - Extract code patterns and vulnerabilities

2. **Dynamic Analysis**
   - Execute symbolic analysis where applicable
   - Run fuzzing campaigns
   - Perform transaction pattern analysis

3. **AI/ML Analysis**
   - Apply machine learning models for pattern recognition
   - Classify vulnerabilities using trained models
   - Predict risk scores and impacts

4. **Cross-Agent Correlation**
   - Combine findings from multiple sources
   - Eliminate duplicates and false positives
   - Correlate related vulnerabilities

#### Phase 4: Results Processing and Aggregation

1. **Finding Normalization**
   - Standardize finding formats across tools
   - Apply consistent severity scoring
   - Add contextual information

2. **Risk Assessment**
   - Calculate CVSS scores
   - Assess business impact
   - Prioritize findings by risk

3. **Compliance Checking**
   - Verify against security standards
   - Check regulatory compliance
   - Generate compliance reports

#### Phase 5: Report Generation and Delivery

1. **Report Compilation**
   - Aggregate all findings and analysis results
   - Generate multiple report formats
   - Include remediation recommendations

2. **Visualization Creation**
   - Generate charts and graphs
   - Create interactive dashboards
   - Produce executive summaries

3. **Output Delivery**
   - Deliver reports via configured channels
   - Store results in databases
   - Trigger follow-up actions

---

## Data Formats and Schemas

### Core Data Structures

#### AuditRequest

```python
@dataclass
class AuditRequest:
    """Request to perform a security audit."""

    id: str
    target: Union[str, List[str]]  # File paths, URLs, or code strings
    target_type: str  # "contract", "protocol", "dapp"
    analysis_config: AnalysisConfig
    reporting_config: ReportingConfig
    metadata: Dict[str, Any]
    timestamp: datetime
    requester: str
```

#### AnalysisConfig

```python
@dataclass
class AnalysisConfig:
    """Configuration for analysis execution."""

    depth: str  # "basic", "standard", "comprehensive", "deep"
    tools: List[str]  # Enabled analysis tools
    timeout: int  # Analysis timeout in seconds
    parallel: bool  # Enable parallel execution
    agents: List[str]  # Enabled audit agents
    custom_rules: List[CustomRule]  # User-defined rules
    exclusions: List[str]  # Files/patterns to exclude
```

#### Finding

The canonical Finding model lives in `src/cai/core/finding.py` and is shared
across all pipeline stages, tools, and report generators:

```python
@dataclass
class Finding:
    """Canonical CAI finding — used by pipeline, tools, and reports."""

    id: str
    vulnerability_type: str
    severity: str
    contract: str
    function_name: str
    location: str

    call_trace: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    taint_path: List[str] = field(default_factory=list)

    cross_contract: bool = False
    external_call_depth: int = 0
    privilege_required: bool = False

    exploit_path: Optional[List[str]] = None
    economic_profitability: Optional[float] = None
    gas_cost_estimate: Optional[float] = None

    fork_verified: bool = False
    invariant_broken: bool = False

    consensus_score: float = 0.0
    rejected_reason: Optional[str] = None

    def is_critical(self) -> bool:
        return (
            self.fork_verified
            and self.invariant_broken
            and self.economic_profitability is not None
            and self.economic_profitability > 0
            and self.consensus_score >= 0.85
        )
```

#### Location

```python
@dataclass
class Location:
    """Location information for findings."""

    file: str
    line: int
    column: int
    function: Optional[str] = None
    contract: Optional[str] = None
    bytecode_offset: Optional[int] = None
```

#### AuditReport

```python
@dataclass
class AuditReport:
    """Complete audit report."""

    audit_id: str
    timestamp: datetime
    target: str
    auditor_version: str
    summary: ReportSummary
    findings: List[Finding]
    recommendations: List[Recommendation]
    compliance: ComplianceResults
    metadata: Dict[str, Any]
    generated_formats: List[str]
```

### JSON Schema Definitions

#### Audit Request Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "id": {"type": "string"},
    "target": {
      "oneOf": [
        {"type": "string"},
        {"type": "array", "items": {"type": "string"}}
      ]
    },
    "target_type": {
      "enum": ["contract", "protocol", "dapp", "api"]
    },
    "analysis_config": {"$ref": "#/definitions/AnalysisConfig"},
    "reporting_config": {"$ref": "#/definitions/ReportingConfig"},
    "metadata": {"type": "object"},
    "timestamp": {"type": "string", "format": "date-time"},
    "requester": {"type": "string"}
  },
  "required": ["id", "target", "target_type", "analysis_config"],
  "definitions": {
    "AnalysisConfig": {
      "type": "object",
      "properties": {
        "depth": {"enum": ["basic", "standard", "comprehensive", "deep"]},
        "tools": {"type": "array", "items": {"type": "string"}},
        "timeout": {"type": "integer", "minimum": 1},
        "parallel": {"type": "boolean"},
        "agents": {"type": "array", "items": {"type": "string"}},
        "custom_rules": {"type": "array", "items": {"$ref": "#/definitions/CustomRule"}},
        "exclusions": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
```

#### Finding Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "id": {"type": "string"},
    "type": {"type": "string"},
    "severity": {
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    },
    "confidence": {"enum": ["high", "medium", "low"]},
    "title": {"type": "string"},
    "description": {"type": "string"},
    "location": {"$ref": "#/definitions/Location"},
    "code_snippet": {"type": "string"},
    "impact": {"type": "string"},
    "recommendation": {"type": "string"},
    "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
    "references": {"type": "array", "items": {"type": "string"}},
    "metadata": {"type": "object"},
    "tags": {"type": "array", "items": {"type": "string"}}
  },
  "required": ["id", "type", "severity", "title", "description"],
  "definitions": {
    "Location": {
      "type": "object",
      "properties": {
        "file": {"type": "string"},
        "line": {"type": "integer", "minimum": 1},
        "column": {"type": "integer", "minimum": 0},
        "function": {"type": "string"},
        "contract": {"type": "string"},
        "bytecode_offset": {"type": "integer"}
      },
      "required": ["file"]
    }
  }
}
```

#### Audit Report Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "audit_id": {"type": "string"},
    "timestamp": {"type": "string", "format": "date-time"},
    "target": {"type": "string"},
    "auditor_version": {"type": "string"},
    "summary": {"$ref": "#/definitions/ReportSummary"},
    "findings": {"type": "array", "items": {"$ref": "#/definitions/Finding"}},
    "recommendations": {"type": "array", "items": {"$ref": "#/definitions/Recommendation"}},
    "compliance": {"$ref": "#/definitions/ComplianceResults"},
    "metadata": {"type": "object"},
    "generated_formats": {"type": "array", "items": {"type": "string"}}
  },
  "required": ["audit_id", "timestamp", "target", "summary", "findings"],
  "definitions": {
    "ReportSummary": {
      "type": "object",
      "properties": {
        "total_findings": {"type": "integer", "minimum": 0},
        "critical": {"type": "integer", "minimum": 0},
        "high": {"type": "integer", "minimum": 0},
        "medium": {"type": "integer", "minimum": 0},
        "low": {"type": "integer", "minimum": 0},
        "info": {"type": "integer", "minimum": 0},
        "risk_score": {"type": "number", "minimum": 0, "maximum": 10},
        "analysis_time": {"type": "number", "minimum": 0},
        "coverage_percentage": {"type": "number", "minimum": 0, "maximum": 100}
      },
      "required": ["total_findings", "risk_score", "analysis_time"]
    }
  }
}
```

### Data Flow Diagrams

#### Contract Analysis Data Flow

```
Contract Source Code
        │
        ▼
   ┌─────────────┐
   │  Parser     │  Extract AST, metadata, dependencies
   └─────────────┘
        │
        ▼
   ┌─────────────┐
   │ Preprocessor│  Normalize, validate, prepare for analysis
   └─────────────┘
        │
        ▼
   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
   │ Static      │     │ Dynamic     │     │ AI/ML       │
   │ Analysis    │     │ Analysis    │     │ Analysis    │
   └─────────────┘     └─────────────┘     └─────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                     ┌─────────────┐
                     │ Correlation │  Deduplicate, correlate findings
                     └─────────────┘
                              │
                              ▼
                        Findings DB
```

#### Report Generation Data Flow

```
Findings DB
     │
     ▼
┌─────────────┐
│ Aggregator  │  Group by severity, type, location
└─────────────┘
     │
     ▼
┌─────────────┐
│ Risk        │  Calculate CVSS, assess impact
│ Assessor    │
└─────────────┘
     │
     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ JSON        │     │ PDF         │     │ HTML        │
│ Generator   │     │ Generator   │     │ Generator   │
└─────────────┘     └─────────────┘     └─────────────┘
     │                     │                     │
     └─────────────────────┼─────────────────────┘
                           ▼
                     Report Files
```

---

## Agent Communication Protocols

### Message Format

All inter-agent communication uses a standardized message format:

```python
@dataclass
class AgentMessage:
    """Standardized message format for agent communication."""

    message_id: str
    sender: str
    recipient: str
    timestamp: datetime
    message_type: str  # "task", "result", "status", "error"
    payload: Dict[str, Any]
    correlation_id: Optional[str] = None
    priority: int = 1  # 1=low, 5=high
    ttl: int = 3600  # Time to live in seconds
```

### Message Types

#### Task Assignment Message

```json
{
  "message_id": "msg_12345",
  "sender": "orchestrator",
  "recipient": "web3_audit_agent",
  "timestamp": "2024-11-05T06:26:13Z",
  "message_type": "task",
  "payload": {
    "task_id": "task_67890",
    "action": "analyze_contract",
    "parameters": {
      "contract_path": "contracts/Token.sol",
      "analysis_type": "comprehensive",
      "timeout": 300
    }
  },
  "correlation_id": null,
  "priority": 3
}
```

#### Result Submission Message

```json
{
  "message_id": "msg_12346",
  "sender": "web3_audit_agent",
  "recipient": "orchestrator",
  "timestamp": "2024-11-05T06:28:45Z",
  "message_type": "result",
  "payload": {
    "task_id": "task_67890",
    "status": "completed",
    "findings": [...],
    "execution_time": 152.3,
    "metadata": {
      "tool_versions": {"slither": "0.10.0"},
      "coverage": 95.2
    }
  },
  "correlation_id": "msg_12345"
}
```

#### Status Update Message

```json
{
  "message_id": "msg_12347",
  "sender": "ml_engine",
  "recipient": "orchestrator",
  "timestamp": "2024-11-05T06:27:22Z",
  "message_type": "status",
  "payload": {
    "task_id": "task_67891",
    "status": "running",
    "progress": 65,
    "current_operation": "Feature extraction",
    "estimated_completion": "2024-11-05T06:32:00Z"
  },
  "correlation_id": "msg_12345"
}
```

#### Error Message

```json
{
  "message_id": "msg_12348",
  "sender": "static_analysis_adapter",
  "recipient": "orchestrator",
  "timestamp": "2024-11-05T06:29:10Z",
  "message_type": "error",
  "payload": {
    "task_id": "task_67892",
    "error_type": "ToolExecutionError",
    "error_message": "Slither analysis failed: timeout",
    "error_details": {
      "tool": "slither",
      "command": "slither contracts/Token.sol --json",
      "exit_code": -1,
      "timeout": 300
    },
    "recoverable": true,
    "retry_suggested": true
  },
  "correlation_id": "msg_12345",
  "priority": 4
}
```

### Communication Patterns

#### Request-Response Pattern

```
Orchestrator → Agent: Task Assignment
      ↓
Agent → Orchestrator: Status Updates
      ↓
Agent → Orchestrator: Result Submission
```

#### Publish-Subscribe Pattern

```
Agent → All Agents: Capability Announcement
Agent → Subscribers: Finding Notifications
Orchestrator → All Agents: Global Configuration Updates
```

#### Pipeline Pattern

```
Agent A → Agent B: Processed Data
Agent B → Agent C: Enhanced Results
Agent C → Orchestrator: Final Output
```

### Message Routing

#### Direct Routing

Messages sent directly to specific agents by ID.

#### Topic-Based Routing

Messages published to topics that interested agents subscribe to:

- `tasks/*` - Task assignments and updates
- `findings/*` - Security findings
- `status/*` - Agent status updates
- `errors/*` - Error notifications

#### Broadcast Routing

System-wide announcements and configuration updates.

### Reliability Mechanisms

#### Message Acknowledgment

```python
# Sender waits for acknowledgment
message = send_message(recipient, payload)
acknowledgment = wait_for_ack(message.id, timeout=30)

if not acknowledgment:
    # Implement retry logic
    retry_message(message)
```

#### Message Persistence

All messages are persisted to ensure delivery even during system restarts.

#### Dead Letter Queue

Undeliverable messages are moved to a dead letter queue for analysis.

---

## Report Generation Process

### Report Types

#### Executive Summary Report

High-level overview for management and stakeholders.

**Contents:**
- Audit summary statistics
- Risk assessment overview
- Key findings and recommendations
- Compliance status

#### Technical Report

Detailed technical findings for developers and auditors.

**Contents:**
- Complete finding details
- Code snippets and locations
- Technical recommendations
- Remediation guidance

#### Compliance Report

Standards compliance assessment.

**Contents:**
- Standards coverage matrix
- Compliance gaps
- Remediation roadmap
- Regulatory requirements

### Report Generation Pipeline

#### Phase 1: Data Collection

1. **Findings Aggregation**
   - Collect all findings from agents
   - Normalize data formats
   - Remove duplicates

2. **Metadata Enrichment**
   - Add contextual information
   - Include code snippets
   - Generate references

#### Phase 2: Analysis and Processing

1. **Risk Calculation**
   - Apply CVSS scoring
   - Assess business impact
   - Calculate risk scores

2. **Finding Correlation**
   - Group related findings
   - Identify root causes
   - Create finding chains

#### Phase 3: Report Assembly

1. **Template Selection**
   - Choose appropriate templates
   - Load formatting rules
   - Configure output options

2. **Content Generation**
   - Populate templates with data
   - Generate visualizations
   - Create executive summaries

#### Phase 4: Output Generation

1. **Format Conversion**
   - Generate JSON reports
   - Create PDF documents
   - Produce HTML dashboards

2. **Quality Assurance**
   - Validate report completeness
   - Check formatting consistency
   - Verify data accuracy

### Report Templates

#### JSON Report Template

```json
{
  "report_metadata": {
    "generated_at": "{{ timestamp }}",
    "generator_version": "{{ version }}",
    "audit_id": "{{ audit_id }}"
  },
  "executive_summary": {
    "total_findings": {{ summary.total_findings }},
    "risk_level": "{{ summary.risk_level }}",
    "key_recommendations": {{ recommendations | tojson }}
  },
  "detailed_findings": {{ findings | tojson }},
  "appendices": {
    "methodology": "{{ methodology }}",
    "tools_used": {{ tools | tojson }},
    "disclaimer": "{{ disclaimer }}"
  }
}
```

#### PDF Report Template Structure

```
Cover Page
├── Title
├── Audit Date
├── Target Information
└── Executive Summary

Table of Contents

Executive Summary
├── Audit Overview
├── Key Findings
├── Risk Assessment
└── Recommendations

Detailed Findings
├── Critical Findings
├── High Findings
├── Medium Findings
├── Low Findings
└── Informational Findings

Compliance Assessment
├── Standards Coverage
├── Compliance Gaps
└── Remediation Plan

Appendices
├── Methodology
├── Tools and Versions
├── Glossary
└── References
```

### Visualization Generation

#### Risk Distribution Chart

```python
def generate_risk_chart(findings: List[Finding]) -> bytes:
    """Generate risk distribution pie chart."""

    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Create pie chart
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    colors = ['#ff0000', '#ff8000', '#ffff00', '#80ff00', '#00ff00']

    plt.figure(figsize=(8, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
    plt.title('Findings by Severity')
    plt.axis('equal')

    # Save to bytes
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
    buffer.seek(0)
    return buffer.getvalue()
```

#### Findings Timeline

```python
def generate_timeline_chart(findings: List[Finding]) -> bytes:
    """Generate findings discovery timeline."""

    # Group findings by time (assuming timestamps are available)
    timeline_data = {}
    for finding in findings:
        timestamp = finding.metadata.get('discovered_at', 'unknown')
        if timestamp != 'unknown':
            date = timestamp.split('T')[0]
            timeline_data[date] = timeline_data.get(date, 0) + 1

    dates = sorted(timeline_data.keys())
    counts = [timeline_data[date] for date in dates]

    plt.figure(figsize=(12, 6))
    plt.plot(dates, counts, marker='o', linestyle='-')
    plt.title('Findings Discovery Timeline')
    plt.xlabel('Date')
    plt.ylabel('Number of Findings')
    plt.xticks(rotation=45)
    plt.grid(True, alpha=0.3)

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
    buffer.seek(0)
    return buffer.getvalue()
```

---

## State Management

### Audit State Lifecycle

```
PENDING → QUEUED → RUNNING → COMPLETING → COMPLETED
    ↓        ↓        ↓          ↓            ↓
 CANCELLED  FAILED   PAUSED    FAILED      ARCHIVED
```

### State Persistence

#### Database Schema

```sql
-- Audit sessions table
CREATE TABLE audit_sessions (
    id VARCHAR(255) PRIMARY KEY,
    target TEXT NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    config JSONB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP
);

-- Audit findings table
CREATE TABLE audit_findings (
    id VARCHAR(255) PRIMARY KEY,
    audit_id VARCHAR(255) REFERENCES audit_sessions(id),
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    location JSONB,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL
);

-- Agent states table
CREATE TABLE agent_states (
    id SERIAL PRIMARY KEY,
    audit_id VARCHAR(255) REFERENCES audit_sessions(id),
    agent_name VARCHAR(100) NOT NULL,
    state JSONB,
    last_updated TIMESTAMP NOT NULL
);
```

#### State Synchronization

```python
class StateManager:
    """Manages audit state persistence and synchronization."""

    def __init__(self, db_connection):
        self.db = db_connection

    def save_audit_state(self, audit_id: str, state: dict):
        """Save complete audit state."""
        with self.db.transaction():
            # Update audit session
            self.db.execute("""
                UPDATE audit_sessions
                SET status = %s, updated_at = NOW()
                WHERE id = %s
            """, (state['status'], audit_id))

            # Save agent states
            for agent_name, agent_state in state['agents'].items():
                self.db.execute("""
                    INSERT INTO agent_states (audit_id, agent_name, state, last_updated)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (audit_id, agent_name)
                    DO UPDATE SET state = EXCLUDED.state, last_updated = NOW()
                """, (audit_id, agent_name, json.dumps(agent_state)))

    def load_audit_state(self, audit_id: str) -> dict:
        """Load complete audit state."""
        # Load audit session
        audit_row = self.db.fetchone("""
            SELECT * FROM audit_sessions WHERE id = %s
        """, (audit_id,))

        if not audit_row:
            raise AuditNotFoundError(f"Audit {audit_id} not found")

        # Load agent states
        agent_rows = self.db.fetchall("""
            SELECT agent_name, state FROM agent_states WHERE audit_id = %s
        """, (audit_id,))

        return {
            'audit': dict(audit_row),
            'agents': {row['agent_name']: json.loads(row['state']) for row in agent_rows}
        }
```

### Checkpointing

```python
class CheckpointManager:
    """Manages audit checkpoints for resumability."""

    def create_checkpoint(self, audit_id: str, checkpoint_data: dict):
        """Create a resumable checkpoint."""
        checkpoint = {
            'audit_id': audit_id,
            'timestamp': datetime.utcnow().isoformat(),
            'data': checkpoint_data,
            'version': '1.0'
        }

        checkpoint_path = f"checkpoints/{audit_id}/checkpoint_{int(time.time())}.json"
        os.makedirs(os.path.dirname(checkpoint_path), exist_ok=True)

        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint, f, indent=2)

        return checkpoint_path

    def load_checkpoint(self, audit_id: str) -> dict:
        """Load the most recent checkpoint for an audit."""
        checkpoint_dir = f"checkpoints/{audit_id}"
        if not os.path.exists(checkpoint_dir):
            raise CheckpointNotFoundError(f"No checkpoints found for audit {audit_id}")

        # Find most recent checkpoint
        checkpoint_files = glob.glob(f"{checkpoint_dir}/checkpoint_*.json")
        if not checkpoint_files:
            raise CheckpointNotFoundError(f"No checkpoint files found for audit {audit_id}")

        latest_checkpoint = max(checkpoint_files, key=os.path.getctime)

        with open(latest_checkpoint, 'r') as f:
            return json.load(f)
```

---

## Error Handling and Recovery

### Error Classification

#### System Errors
- **ConfigurationError**: Invalid configuration or missing parameters
- **ResourceError**: Insufficient resources (memory, disk, CPU)
- **NetworkError**: Connectivity issues with external services
- **DatabaseError**: Database connectivity or query failures

#### Analysis Errors
- **ToolError**: External tool execution failures
- **ParseError**: Input parsing or format validation failures
- **TimeoutError**: Analysis operations exceeding time limits
- **ValidationError**: Input validation failures

#### Agent Errors
- **AgentCommunicationError**: Inter-agent communication failures
- **AgentTimeoutError**: Agent operations timing out
- **AgentConfigurationError**: Agent-specific configuration issues

### Recovery Strategies

#### Automatic Recovery

```python
class ErrorRecoveryManager:
    """Manages automatic error recovery strategies."""

    def __init__(self):
        self.recovery_strategies = {
            'ToolError': self._recover_tool_error,
            'TimeoutError': self._recover_timeout_error,
            'NetworkError': self._recover_network_error
        }

    def recover(self, error: Exception, context: dict) -> RecoveryAction:
        """Determine and execute recovery strategy."""

        error_type = type(error).__name__

        if error_type in self.recovery_strategies:
            return self.recovery_strategies[error_type](error, context)
        else:
            return RecoveryAction(type='escalate', message=str(error))

    def _recover_tool_error(self, error: ToolError, context: dict) -> RecoveryAction:
        """Recover from tool execution errors."""
        tool_name = context.get('tool_name')

        # Try alternative tool
        alternatives = self._get_alternative_tools(tool_name)
        if alternatives:
            return RecoveryAction(
                type='retry_with_alternative',
                alternative_tool=alternatives[0],
                message=f"Switching to alternative tool: {alternatives[0]}"
            )

        # Retry with different parameters
        return RecoveryAction(
            type='retry_with_params',
            new_params={'timeout': context.get('timeout', 300) * 2},
            message="Retrying with extended timeout"
        )

    def _recover_timeout_error(self, error: TimeoutError, context: dict) -> RecoveryAction:
        """Recover from timeout errors."""
        # Reduce analysis scope
        return RecoveryAction(
            type='reduce_scope',
            new_scope='basic',
            message="Reducing analysis scope to basic level"
        )

    def _recover_network_error(self, error: NetworkError, context: dict) -> RecoveryAction:
        """Recover from network errors."""
        # Implement exponential backoff
        return RecoveryAction(
            type='retry_with_backoff',
            backoff_seconds=60,
            max_retries=3,
            message="Retrying with exponential backoff"
        )
```

#### Manual Intervention

For errors requiring human intervention:

```python
class ManualInterventionHandler:
    """Handles errors requiring manual intervention."""

    def __init__(self, notification_system):
        self.notifications = notification_system

    def handle_manual_intervention(self, error: Exception, context: dict):
        """Handle errors requiring manual intervention."""

        # Create intervention request
        intervention = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'timestamp': datetime.utcnow().isoformat(),
            'possible_actions': self._suggest_actions(error, context)
        }

        # Notify administrators
        self.notifications.send_alert(
            title="Manual Intervention Required",
            message=f"Audit {context.get('audit_id')} requires manual intervention",
            details=intervention
        )

        # Pause audit
        audit_manager.pause_audit(context.get('audit_id'))

    def _suggest_actions(self, error: Exception, context: dict) -> List[str]:
        """Suggest possible manual actions."""
        suggestions = []

        if isinstance(error, ToolError):
            suggestions.extend([
                "Check tool installation and version",
                "Verify tool configuration and permissions",
                "Review tool-specific documentation",
                "Consider using alternative tool"
            ])

        if isinstance(error, ConfigurationError):
            suggestions.extend([
                "Review configuration file syntax",
                "Check environment variables",
                "Validate parameter values",
                "Consult configuration documentation"
            ])

        return suggestions
```

### Error Reporting

```python
class ErrorReporter:
    """Centralized error reporting and aggregation."""

    def __init__(self, db_connection, metrics_system):
        self.db = db_connection
        self.metrics = metrics_system

    def report_error(self, error: Exception, context: dict):
        """Report error to centralized system."""

        error_record = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'stack_trace': traceback.format_exc(),
            'context': context,
            'timestamp': datetime.utcnow().isoformat(),
            'audit_id': context.get('audit_id'),
            'agent_name': context.get('agent_name'),
            'severity': self._calculate_error_severity(error, context)
        }

        # Store in database
        self.db.execute("""
            INSERT INTO error_logs
            (error_type, error_message, stack_trace, context, timestamp, audit_id, agent_name, severity)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            error_record['error_type'],
            error_record['error_message'],
            error_record['stack_trace'],
            json.dumps(error_record['context']),
            error_record['timestamp'],
            error_record['audit_id'],
            error_record['agent_name'],
            error_record['severity']
        ))

        # Update metrics
        self.metrics.increment_counter(f"errors.{error_record['error_type']}")
        self.metrics.increment_counter(f"errors.severity.{error_record['severity']}")

        # Trigger alerts for critical errors
        if error_record['severity'] == 'critical':
            self._trigger_critical_alert(error_record)

    def _calculate_error_severity(self, error: Exception, context: dict) -> str:
        """Calculate error severity level."""
        if isinstance(error, (SystemExit, KeyboardInterrupt)):
            return 'critical'
        elif isinstance(error, (DatabaseError, NetworkError)):
            return 'high'
        elif isinstance(error, TimeoutError):
            return 'medium'
        else:
            return 'low'
```

---

## Performance Optimization

### Parallel Processing

#### Task Parallelization

```python
import asyncio
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp

class ParallelProcessor:
    """Handles parallel processing of audit tasks."""

    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()
        self.executor = ProcessPoolExecutor(max_workers=self.max_workers)

    async def process_parallel(self, tasks: List[Dict]) -> List[Dict]:
        """Process tasks in parallel."""

        # Create async tasks
        async_tasks = []
        for task in tasks:
            async_task = asyncio.get_event_loop().run_in_executor(
                self.executor,
                self._execute_task,
                task
            )
            async_tasks.append(async_task)

        # Wait for all tasks to complete
        results = await asyncio.gather(*async_tasks, return_exceptions=True)

        # Handle results and exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Handle task failure
                processed_results.append({
                    'task_id': tasks[i]['id'],
                    'status': 'failed',
                    'error': str(result)
                })
            else:
                processed_results.append(result)

        return processed_results

    def _execute_task(self, task: Dict) -> Dict:
        """Execute individual task."""
        task_type = task.get('type')

        if task_type == 'static_analysis':
            return self._run_static_analysis(task)
        elif task_type == 'ml_analysis':
            return self._run_ml_analysis(task)
        else:
            raise ValueError(f"Unknown task type: {task_type}")
```

#### Load Balancing

```python
class LoadBalancer:
    """Distributes workload across available resources."""

    def __init__(self, workers: List[Dict]):
        self.workers = workers  # [{'id': 'worker1', 'capacity': 10, 'current_load': 0}]
        self.task_queue = asyncio.Queue()

    def distribute_task(self, task: Dict) -> str:
        """Distribute task to least loaded worker."""

        # Find worker with lowest load
        available_workers = [w for w in self.workers if w['current_load'] < w['capacity']]
        if not available_workers:
            raise ResourceExhaustedError("No available workers")

        best_worker = min(available_workers, key=lambda w: w['current_load'])

        # Assign task to worker
        best_worker['current_load'] += task.get('weight', 1)

        return best_worker['id']

    async def process_queue(self):
        """Process tasks from queue."""
        while True:
            task = await self.task_queue.get()

            try:
                worker_id = self.distribute_task(task)
                await self._send_to_worker(worker_id, task)
            except Exception as e:
                print(f"Failed to distribute task {task['id']}: {e}")
            finally:
                self.task_queue.task_done()
```

### Caching and Memoization

#### Analysis Result Caching

```python
import hashlib
from functools import lru_cache
from typing import Dict, Any
import pickle

class AnalysisCache:
    """Caches analysis results to improve performance."""

    def __init__(self, cache_dir: str = "./.audit_cache", max_size: int = 1000):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size = max_size
        self._cache_index: Dict[str, str] = {}  # key -> file_path

    def get_cache_key(self, target: str, analysis_type: str, config: Dict) -> str:
        """Generate cache key from inputs."""
        key_data = {
            'target': target,
            'analysis_type': analysis_type,
            'config': config
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def get(self, key: str) -> Any:
        """Retrieve cached result."""
        if key not in self._cache_index:
            return None

        cache_file = self.cache_dir / self._cache_index[key]

        if not cache_file.exists():
            del self._cache_index[key]
            return None

        try:
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        except Exception:
            # Corrupted cache file
            cache_file.unlink()
            del self._cache_index[key]
            return None

    def put(self, key: str, value: Any):
        """Store result in cache."""
        # Evict old entries if cache is full
        if len(self._cache_index) >= self.max_size:
            self._evict_oldest()

        # Generate cache file path
        cache_file = self.cache_dir / f"{key}.pkl"

        # Store result
        with open(cache_file, 'wb') as f:
            pickle.dump(value, f)

        # Update index
        self._cache_index[key] = f"{key}.pkl"

    def _evict_oldest(self):
        """Evict oldest cache entries."""
        # Simple LRU eviction - remove half of entries
        items_to_remove = len(self._cache_index) // 2

        for key in list(self._cache_index.keys())[:items_to_remove]:
            cache_file = self.cache_dir / self._cache_index[key]
            if cache_file.exists():
                cache_file.unlink()
            del self._cache_index[key]

# Usage with memoization
@lru_cache(maxsize=128)
def cached_static_analysis(target: str, tool: str, config_hash: str) -> Dict:
    """Cached static analysis function."""
    cache = AnalysisCache()
    cache_key = cache.get_cache_key(target, f"static_{tool}", {"config_hash": config_hash})

    # Check cache first
    cached_result = cache.get(cache_key)
    if cached_result:
        return cached_result

    # Perform analysis
    result = perform_static_analysis(target, tool)

    # Cache result
    cache.put(cache_key, result)

    return result
```

### Resource Optimization

#### Memory Management

```python
class MemoryManager:
    """Manages memory usage during analysis."""

    def __init__(self, max_memory_gb: float = 4.0):
        self.max_memory_gb = max_memory_gb
        self.process = psutil.Process()

    def check_memory_usage(self) -> float:
        """Check current memory usage in GB."""
        memory_info = self.process.memory_info()
        return memory_info.rss / (1024 ** 3)  # Convert to GB

    def should_reduce_load(self) -> bool:
        """Check if memory usage is too high."""
        current_usage = self.check_memory_usage()
        return current_usage > self.max_memory_gb * 0.8  # 80% threshold

    def optimize_memory(self):
        """Perform memory optimization."""
        # Force garbage collection
        gc.collect()

        # Clear any caches if necessary
        if hasattr(self, 'analysis_cache'):
            self.analysis_cache.clear()

        # Reduce worker pool size if needed
        if self.should_reduce_load():
            self._reduce_worker_pool()

    def _reduce_worker_pool(self):
        """Reduce the number of active workers."""
        # Implementation depends on parallel processing setup
        pass
```

#### CPU Optimization

```python
class CPUOptimizer:
    """Optimizes CPU usage for analysis tasks."""

    def __init__(self):
        self.cpu_count = mp.cpu_count()

    def get_optimal_worker_count(self, task_type: str) -> int:
        """Get optimal number of workers for task type."""

        if task_type == 'cpu_intensive':
            # Use all cores for CPU-intensive tasks
            return self.cpu_count
        elif task_type == 'io_intensive':
            # Use more workers for I/O intensive tasks
            return self.cpu_count * 2
        elif task_type == 'memory_intensive':
            # Use fewer workers for memory-intensive tasks
            return max(1, self.cpu_count // 2)
        else:
            return max(1, self.cpu_count - 1)

    def throttle_if_needed(self):
        """Throttle processing if CPU usage is too high."""
        cpu_percent = psutil.cpu_percent(interval=1)

        if cpu_percent > 90:
            # High CPU usage - add delay
            time.sleep(0.1)
        elif cpu_percent > 75:
            # Moderate CPU usage - slight delay
            time.sleep(0.05)
```

This comprehensive documentation covers the workflow, data flow, agent communication, and performance optimization aspects of the Web3 Security Auditing AI System.