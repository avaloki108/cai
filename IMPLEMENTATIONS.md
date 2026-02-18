I'll explore the current directory to understand what tool you're referring to, then analyze it for potential web3 vulnerability detection improvements.
Let me explore this CAI tool further to understand its capabilities for web3 vulnerability detection.
Let me explore the web3 security tools implementation in more detail:
Now I have a comprehensive understanding of CAI's web3 security capabilities. Let me compile a detailed list of upgrade recommendations:

---

# CAI Web3 Vulnerability Detection - Upgrade Recommendations

Based on my analysis of the codebase, here are potential upgrades categorized by priority and domain:

## 1. Cross-Chain & Bridge Security (HIGH PRIORITY)

**Current State**: Basic bridge pattern detection exists but is limited.

**Upgrades:**
- **Dedicated Bridge Analyzer**: Create `protocols/bridge_analyzer.py` with comprehensive checks for:
  - Message replay protection across chains
  - Chain ID validation in signatures
  - Nonce management vulnerabilities
  - Oracle/validator collusion scenarios
  - Gas griefing on destination chains
  - Stuck message recovery paths

- **L2-Specific Analysis**: Add analyzers for:
  - Optimistic rollup challenge period exploits
  - ZK rollup proof verification
  - Sequencer centralization risks
  - Force-inclusion edge cases

- **Protocol Integrations**: Add connectors for LayerZero, Wormhole, CCIP, Axelar, and Stargate-specific vulnerability patterns

## 2. MEV & Transaction Ordering (HIGH PRIORITY)

**Current State**: Basic sandwich attack detection exists.

**Upgrades:**
- **MEV Simulation Engine**: Integrate with Flashbots/MEV-Share simulation to:
  - Detect extractable value from contract interactions
  - Identify frontrunning vectors in AMM swaps
  - Analyze private mempool exposure risks

- **Time-Bandit Attack Detection**: Add analysis for:
  - Reorg-vulnerable profit extraction
  - Multi-block MEV opportunities
  - JIT liquidity manipulation

- **Backrunning Opportunity Detection**: Identify patterns where state changes create profitable backrun opportunities

## 3. Advanced DeFi Protocol Analysis (HIGH PRIORITY)

**Current State**: Good foundation with oracle/flash loan analysis.

**Upgrades:**
- **Additional Protocol Analyzers**:
  - `protocols/perpetuals_analyzer.py` - Funding rate manipulation, liquidation cascades
  - `protocols/options_analyzer.py` - Greeks manipulation, settlement attacks
  - `protocols/yield_aggregator_analyzer.py` - Strategy vault sandwich, harvest timing
  - `protocols/stablecoin_analyzer.py` - Depeg scenarios, collateral attacks

- **Composability Risk Analysis**:
  - Protocol dependency graphing
  - Contagion risk scoring
  - Liquidity fragmentation detection

- **Economic Attack Simulation**:
  - Token price impact modeling
  - Liquidity depth analysis pre/post attack
  - Multi-step attack path optimization

## 4. Access Control & Governance (MEDIUM PRIORITY)

**Current State**: Basic access control detection.

**Upgrades:**
- **Governance Attack Vectors**:
  - Flash loan governance attacks (borrow, vote, return)
  - Proposal griefing detection
  - Timelock bypass scenarios
  - Emergency function abuse patterns

- **Role-Based Analysis**:
  - Privilege escalation paths
  - Admin key centralization risks
  - Multi-sig configuration weaknesses

- **Upgrade Safety**:
  - Storage collision detection across upgrades
  - Initializer re-entrancy
  - Implementation contract takeover

## 5. Storage & Memory Analysis (MEDIUM PRIORITY)

**Current State**: Limited storage analysis.

**Upgrades:**
- **Storage Layout Analyzer**:
  - Cross-version storage collision detection
  - Uninitialized storage pointer attacks
  - Storage packing vulnerabilities

- **Memory Safety**:
  - Transient storage (EIP-1153) analysis
  - Memory expansion attacks
  - Inline assembly memory safety

## 6. New Vulnerability Classes (HIGH PRIORITY)

**Add Detection For:**
- **EIP-4337 Account Abstraction**:
  - Paymaster drainage attacks
  - Bundler manipulation
  - UserOp replay attacks

- **ERC-4626 Enhancements** (extend current):
  - Virtual share attacks
  - Donation attacks on empty vaults
  - Decimal mismatch exploits

- **Restaking Protocols**:
  - Slashing cascades
  - AVS security risks
  - Withdrawal queue manipulation

- **Intent-Based Systems**:
  - Solver collusion
  - Intent front-running
  - Partial fill manipulation

## 7. On-Chain Data Integration (HIGH PRIORITY)

**Current State**: Limited blockchain interaction.

**Upgrades:**
- **Live Contract Analysis**:
  - Fetch deployed bytecode for analysis
  - Compare implementation vs proxy storage
  - Historical storage slot analysis

- **Transaction Simulation**:
  - Tenderly/Foundry fork integration for live simulations
  - Reproduce known exploits on forks
  - Attack validation before reporting

- **On-Chain Monitoring Hooks**:
  - Real-time vulnerability monitoring
  - Anomaly detection integration
  - Post-deployment security alerts

## 8. Exploit DB & Learning (MEDIUM PRIORITY)

**Current State**: Basic knowledge base.

**Upgrades:**
- **Exploit Pattern Database**:
  - Comprehensive DB of past exploits with signatures
  - Automated pattern extraction from post-mortems
  - Similarity scoring against known exploits

- **Self-Improving Detection**:
  - Feedback loop from validated findings
  - False positive tracking and learning
  - Custom detector generation from new patterns

## 9. Fuzzing Enhancements (MEDIUM PRIORITY)

**Current State**: Echidna/Medusa integration exists.

**Upgrades:**
- **Invariant Generation**:
  - AI-assisted invariant discovery
  - Property template library for common patterns
  - Automatic invariant validation

- **Corpus Sharing**:
  - Cross-project corpus reuse
  - Protocol-specific seed generation
  - Coverage-maximizing mutation strategies

- **Differential Fuzzing**:
  - Compare implementations against spec
  - Multi-version differential testing
  - Fork-based fuzzing against mainnet state

## 10. Reporting & Integration (LOW PRIORITY)

**Upgrades:**
- **Structured Output Formats**:
  - SARIF export for IDE integration
  - CodeQL query generation
  - GitHub Security Advisory format

- **Audit Report Generation**:
  - Professional audit report templates
  - Finding de-duplication and grouping
  - Remediation suggestion engine

- **CI/CD Integration**:
  - GitHub Actions templates
  - Pre-commit hooks
  - Pull request annotations

## 11. Missing Tool Integrations

**Add Integrations For:**
- **Wake** - Python-based Solidity development/testing
- **Heimdall** - EVM bytecode decompiler
- **Pyrometer** - Abstract interpretation analyzer
- **Halmos** - Symbolic testing with Foundry
- **Kontrol** - K Framework formal verification
- **Aderyn** - Rust-based static analyzer (faster than Slither)

## 12. AI/LLM Enhancements

**Current State**: IRIS integration exists.

**Upgrades:**
- **Context-Aware Analysis**:
  - Protocol documentation parsing
  - README/spec understanding
  - Intent extraction from comments

- **Multi-Agent Orchestration**:
  - Specialized agents for different vuln classes
  - Adversarial agent for exploit validation
  - Reviewer agent for false positive reduction

- **RAG Improvements**:
  - Audit report corpus for similar findings
  - Academic paper integration
  - Real-time Twitter/Discord security intel

---

## Implementation Priority Matrix

| Category | Impact | Effort | Priority |
|----------|--------|--------|----------|
| Cross-Chain/Bridge | Very High | High | 1 |
| MEV Analysis | Very High | Medium | 2 |
| DeFi Protocol Analyzers | High | Medium | 3 |
| On-Chain Data Integration | High | Medium | 4 |
| New Vuln Classes (AA, Restaking) | High | Medium | 5 |
| Exploit DB/Learning | Medium | Low | 6 |
| Access Control/Governance | Medium | Medium | 7 |
| Fuzzing Enhancements | Medium | Medium | 8 |
| Tool Integrations | Medium | Low | 9 |
| AI/LLM Enhancements | Medium | High | 10 |
| Reporting | Low | Low | 11 |

---

Want me to dive deeper into any specific category or create a detailed implementation plan for any of these upgrades?
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


Now I have a comprehensive understanding of the CAI framework. Let me create the detailed implementation plan.

---

# CAI Web3 Cybersecurity AI Agents - Comprehensive Implementation Plan

## Executive Summary

This document provides a detailed implementation plan for twelve specialized cybersecurity AI agents within the CAI framework. These agents form a coordinated system for automated smart contract vulnerability detection, verification, and exploitation proof generation.

---

## Part 1: Agent Technical Requirements

### Agent 1: Skeptic Alpha - Logical Denier

**Purpose**: Attack vulnerability claims through logical analysis

**Location**: `src/cai/agents/skeptic_alpha.py`

**Technical Requirements**:
```
Core Capabilities:
├── Assumption chain breaking
├── Logical contradiction detection
├── Missing precondition identification
├── Causal relationship challenge
└── Circular reasoning exposure

Dependencies:
├── cai.sdk.agents (Agent, OpenAIChatCompletionsModel, function_tool)
├── openai.AsyncOpenAI
└── cai.tools.web3_security.enhancements.attack_economics

Tools Required:
├── challenge_assumptions() - Analyze stated assumptions for flaws
├── find_contradictions() - Identify logical inconsistencies
├── verify_preconditions() - Check if preconditions are met
└── break_causal_chain() - Challenge cause-effect relationships

Model Requirements:
├── Primary: alias1 / gpt-4o (reasoning-heavy)
├── Context Window: 128K+ tokens
└── Temperature: 0.1-0.3 (precise reasoning)
```

---

### Agent 2: Skeptic Beta - Economic Reality Checker

**Purpose**: Challenge economic viability of exploit claims

**Location**: `src/cai/agents/skeptic_beta.py`

**Technical Requirements**:
```
Core Capabilities:
├── Gas cost analysis
├── Flash loan fee calculations
├── MEV competition modeling
├── Slippage impact estimation
└── Net profitability determination

Dependencies:
├── cai.tools.web3_security.enhancements.attack_economics
├── cai.tools.web3_security.enhancements.exploit_scorer
└── External: Etherscan API, DEX price feeds

Tools Required:
├── calculate_attack_profitability() - Full economic simulation
├── estimate_gas_costs() - Multi-scenario gas estimation
├── model_mev_competition() - MEV searcher advantage modeling
└── compute_slippage_impact() - Liquidity depth analysis

Model Requirements:
├── Primary: gpt-4o / claude-3.5-sonnet (numerical reasoning)
├── Context Window: 64K+ tokens
└── Temperature: 0.0 (deterministic calculations)
```

---

### Agent 3: Skeptic Gamma - Code Reality Checker

**Purpose**: Verify code-level claims against actual implementation

**Location**: `src/cai/agents/skeptic_gamma.py`

**Technical Requirements**:
```
Core Capabilities:
├── Source code verification
├── Bytecode analysis
├── Storage layout validation
├── Function signature matching
└── Modifier effectiveness checking

Dependencies:
├── cai.tools.web3_security.slither (static analysis)
├── cai.tools.web3_security.mythril (symbolic execution)
└── External: Foundry, solc compiler

Tools Required:
├── verify_code_claim() - Match claim to actual code
├── analyze_modifiers() - Check modifier effectiveness
├── trace_storage_access() - Verify storage assumptions
└── compare_bytecode() - Deployed vs source verification

Model Requirements:
├── Primary: claude-3.5-sonnet (code understanding)
├── Context Window: 200K+ tokens
└── Temperature: 0.0-0.2 (precise code analysis)
```

---

### Agent 4: Critic Agent - GPTLens Adversarial Review

**Purpose**: Three-dimensional finding evaluation (Correctness, Severity, Profitability)

**Location**: `src/cai/agents/critic.py`

**Technical Requirements**:
```
Core Capabilities:
├── Correctness scoring (0-10)
├── Severity assessment (0-10)
├── Profitability analysis (0-10)
├── Threshold-based filtering (reject if any < 5)
└── Detailed reasoning output

Dependencies:
├── cai.sdk.agents (Agent, function_tool)
├── dataclasses (CriticScore, CriticEvaluation)
└── enum (Verdict: ACCEPT, REJECT, NEEDS_MORE_INFO)

Tools Required:
├── evaluate_finding() - Complete three-dimensional evaluation
├── score_correctness() - Logical soundness assessment
├── score_severity() - Impact magnitude estimation
├── score_profitability() - Economic viability rating

Model Requirements:
├── Primary: gpt-4o / alias1 (balanced reasoning)
├── Context Window: 128K+ tokens
└── Temperature: 0.2-0.4 (calibrated judgment)
```

---

### Agent 5: Planner Agent - Pre-Act Multi-Step Planning

**Purpose**: Generate comprehensive audit execution plans

**Location**: `src/cai/agents/planner.py`

**Technical Requirements**:
```
Core Capabilities:
├── Multi-step plan generation
├── Agent assignment per step
├── Dependency graph construction
├── Adaptive plan refinement
└── Progress tracking

Dependencies:
├── cai.sdk.agents (Agent, function_tool)
├── dataclasses (PlanStep, AuditPlan)
├── enum (StepStatus: PENDING, IN_PROGRESS, COMPLETED, FAILED, SKIPPED)
└── datetime (timestamps)

Tools Required:
├── generate_plan() - Create initial audit plan
├── refine_plan() - Update based on tool outputs
├── assign_agent() - Match steps to appropriate agents
├── track_progress() - Monitor execution status

Model Requirements:
├── Primary: gpt-4o / o3-mini (planning capability)
├── Context Window: 128K+ tokens
└── Temperature: 0.3-0.5 (creative planning)
```

---

### Agent 6: Exploit Synthesizer - PoC Development

**Purpose**: Generate working exploits from confirmed vulnerabilities

**Location**: `src/cai/agents/exploit_synthesizer.py`

**Technical Requirements**:
```
Core Capabilities:
├── Exploit pattern matching
├── Foundry test generation
├── Attack step sequencing
├── Assertion construction
└── Failure analysis

Dependencies:
├── cai.sdk.agents (function_tool)
├── cai.tools.web3_security.foundry (Foundry integration)
├── cai.tools.web3_security.fork_test (fork testing)
└── External: forge CLI

Tools Required:
├── synthesize_exploit() - Generate complete exploit code
├── generate_exploit_code() - Pattern-based code generation
├── run_forge_test() - Execute and verify exploit
├── analyze_failure() - Document blocking conditions

Model Requirements:
├── Primary: claude-3.5-sonnet / gpt-4o (code generation)
├── Context Window: 128K+ tokens
└── Temperature: 0.2-0.4 (balanced creativity)
```

---

### Agent 7: PoC Generator - Foundry Test Builder

**Purpose**: Create compilable Foundry test files for vulnerabilities

**Location**: `src/cai/agents/poc_generator.py`

**Technical Requirements**:
```
Core Capabilities:
├── Foundry test structure generation
├── Setup function creation
├── Exploit step implementation
├── Assertion design
└── Comment documentation

Dependencies:
├── cai.sdk.agents (Agent, OpenAIChatCompletionsModel)
├── openai.AsyncOpenAI
└── External: forge-std/Test.sol

Tools Required:
├── generate_poc() - Complete test file generation
├── create_setup() - Environment initialization
├── implement_exploit() - Attack step coding
└── design_assertions() - Impact verification

Model Requirements:
├── Primary: claude-3.5-sonnet (Solidity expertise)
├── Context Window: 200K+ tokens
└── Temperature: 0.1-0.3 (precise code)
```

---

### Agent 8: Manager Vuln - Vulnerability Coordinator

**Purpose**: Coordinate vulnerability detection across tools

**Location**: `src/cai/agents/manager_vuln.py`

**Technical Requirements**:
```
Core Capabilities:
├── Multi-tool orchestration
├── Finding aggregation
├── Duplicate detection
├── Priority ranking
└── Coverage tracking

Dependencies:
├── cai.tools.web3_security.enhancements.multi_tool_orchestrator
├── cai.tools.web3_security.validate_findings
└── cai.tools.web3_security.triage

Tools Required:
├── orchestrate_tools() - Run multiple analysis tools
├── aggregate_findings() - Combine results
├── deduplicate() - Remove redundant findings
├── rank_priorities() - Order by severity/exploitability

Model Requirements:
├── Primary: gpt-4o (coordination)
├── Context Window: 128K+ tokens
└── Temperature: 0.2 (consistent decisions)
```

---

### Agent 9: Manager Economic - Economic Analysis Coordinator

**Purpose**: Coordinate economic vulnerability analysis

**Location**: `src/cai/agents/manager_economic.py`

**Technical Requirements**:
```
Core Capabilities:
├── DeFi protocol analysis
├── Economic invariant checking
├── Flash loan attack modeling
├── Oracle manipulation detection
└── MEV exposure assessment

Dependencies:
├── cai.tools.web3_security.enhancements.defi_analyzer
├── cai.tools.web3_security.enhancements.attack_economics
├── cai.tools.web3_security.protocols.*
└── External: DEX APIs, price feeds

Tools Required:
├── analyze_defi_protocol() - Protocol-specific analysis
├── check_economic_invariants() - Invariant validation
├── model_flash_loan_attack() - Flash loan scenarios
├── assess_mev_exposure() - MEV vulnerability rating

Model Requirements:
├── Primary: gpt-4o / claude-3.5-sonnet (economic reasoning)
├── Context Window: 128K+ tokens
└── Temperature: 0.1-0.3 (precise economics)
```

---

### Agent 10: Manager Access - Access Control Coordinator

**Purpose**: Coordinate access control and privilege analysis

**Location**: `src/cai/agents/manager_access.py`

**Technical Requirements**:
```
Core Capabilities:
├── Role-based access analysis
├── Privilege escalation detection
├── Modifier effectiveness verification
├── Admin key risk assessment
└── Governance attack modeling

Dependencies:
├── cai.tools.web3_security.slither (access control detectors)
├── cai.tools.web3_security.enhancements.attack_graph
└── Custom access control patterns

Tools Required:
├── analyze_roles() - Map role hierarchy
├── detect_privilege_escalation() - Find escalation paths
├── verify_modifiers() - Check modifier strength
├── assess_admin_risks() - Centralization analysis

Model Requirements:
├── Primary: gpt-4o (security reasoning)
├── Context Window: 128K+ tokens
└── Temperature: 0.1-0.2 (conservative analysis)
```

---

### Agent 11: Attributor - Finding Attribution

**Purpose**: Attribute findings to root causes and responsible code

**Location**: `src/cai/agents/attributor.py`

**Technical Requirements**:
```
Core Capabilities:
├── Root cause analysis
├── Code location attribution
├── Responsibility assignment
├── Impact chain tracing
└── Fix recommendation

Dependencies:
├── cai.tools.web3_security.slither (call graphs)
├── cai.tools.web3_security.symbolic.correlator
└── cai.tools.web3_security.enhancements.attack_graph

Tools Required:
├── trace_root_cause() - Find vulnerability origin
├── attribute_code() - Map to specific lines/functions
├── build_impact_chain() - Show vulnerability propagation
├── recommend_fix() - Suggest remediation

Model Requirements:
├── Primary: claude-3.5-sonnet (code tracing)
├── Context Window: 200K+ tokens
└── Temperature: 0.1-0.2 (precise attribution)
```

---

### Agent 12: Web3 Discovery Agent - Reconnaissance

**Purpose**: Initial target reconnaissance and context building

**Location**: `src/cai/agents/web3_discovery_agent.py`

**Technical Requirements**:
```
Core Capabilities:
├── Repository structure analysis
├── Framework detection (Foundry/Hardhat)
├── Protocol type classification
├── Dependency mapping
└── Attack surface enumeration

Dependencies:
├── cai.tools.web3_security.enhancements.repo_context
├── cai.tools.reconnaissance.filesystem
└── External: GitHub API, Etherscan

Tools Required:
├── detect_web3_repo_context() - Full context detection
├── classify_protocol() - DeFi/NFT/Governance/Bridge
├── map_dependencies() - External contract mapping
├── enumerate_attack_surface() - Entry point identification

Model Requirements:
├── Primary: gpt-4o-mini / claude-3-haiku (fast recon)
├── Context Window: 64K+ tokens
└── Temperature: 0.0-0.2 (factual discovery)
```

---

## Part 2: Implementation Timeline

### Phase 1: Foundation (Weeks 1-4)

```
Week 1-2: Core Infrastructure
├── Day 1-3: Agent factory system enhancement
│   ├── Extend factory.py for new agent types
│   ├── Add model configuration per agent
│   └── Implement agent registry
├── Day 4-7: Base agent template creation
│   ├── Standardize agent structure
│   ├── Create shared utilities
│   └── Define common interfaces
├── Day 8-10: Tool integration framework
│   ├── Tool discovery mechanism
│   ├── Tool dependency injection
│   └── Tool result caching
└── Day 11-14: Testing infrastructure
    ├── Unit test templates
    ├── Integration test harness
    └── Benchmark integration hooks

Week 3-4: Core Agents Implementation
├── Planner Agent (priority: critical path)
│   ├── Plan generation logic
│   ├── Step dependency resolution
│   └── Progress tracking
├── Web3 Discovery Agent (priority: entry point)
│   ├── Repo context detection
│   ├── Framework identification
│   └── Attack surface mapping
└── Critic Agent (priority: quality gate)
    ├── Three-dimensional scoring
    ├── Threshold filtering
    └── Verdict generation
```

**Milestone 1**: Core orchestration working - Planner can generate plans, Discovery can analyze repos, Critic can evaluate findings.

---

### Phase 2: Skeptic Layer (Weeks 5-8)

```
Week 5-6: Skeptic Alpha
├── Assumption challenge logic
├── Contradiction detection
├── Precondition verification
└── Unit tests + benchmarks

Week 6-7: Skeptic Beta
├── Economic profitability calculations
├── Gas cost modeling
├── MEV competition analysis
└── Integration with attack_economics

Week 7-8: Skeptic Gamma
├── Code verification tools
├── Bytecode analysis integration
├── Modifier effectiveness checking
└── Slither/Mythril tool connections
```

**Milestone 2**: Adversarial review layer operational - All three skeptics can challenge findings independently.

---

### Phase 3: Manager Layer (Weeks 9-12)

```
Week 9-10: Manager Vuln
├── Multi-tool orchestration
├── Finding aggregation logic
├── Deduplication algorithms
└── Priority ranking system

Week 10-11: Manager Economic
├── DeFi protocol analyzers
├── Flash loan modeling
├── Oracle manipulation detection
└── Protocol-specific integrations

Week 11-12: Manager Access
├── Role hierarchy analysis
├── Privilege escalation detection
├── Modifier verification
└── Governance attack modeling
```

**Milestone 3**: Coordination layer complete - Managers can orchestrate domain-specific analysis.

---

### Phase 4: Synthesis Layer (Weeks 13-16)

```
Week 13-14: Exploit Synthesizer
├── Pattern-based exploit generation
├── Foundry test integration
├── Failure analysis system
└── Forge execution wrapper

Week 14-15: PoC Generator
├── Test file templates
├── Setup function generation
├── Assertion design logic
└── Comment documentation

Week 15-16: Attributor
├── Root cause tracing
├── Code attribution logic
├── Impact chain building
└── Fix recommendation engine
```

**Milestone 4**: Synthesis layer operational - System can generate working PoCs for confirmed vulnerabilities.

---

### Phase 5: Integration & Optimization (Weeks 17-20)

```
Week 17-18: Full System Integration
├── Agent handoff protocol
├── Message passing optimization
├── State management
└── Error recovery

Week 18-19: Performance Optimization
├── Parallel execution tuning
├── Caching strategies
├── Token usage optimization
└── Latency reduction

Week 19-20: Final Testing & Documentation
├── End-to-end integration tests
├── Benchmark validation
├── Documentation completion
└── User acceptance testing
```

**Milestone 5**: Production-ready system with full agent coordination.

---

## Part 3: Resource Allocation

### Human Resources

| Role | Count | Allocation | Responsibilities |
|------|-------|------------|------------------|
| Lead Architect | 1 | 100% | System design, code review |
| Backend Engineers | 2 | 100% | Agent implementation |
| ML Engineer | 1 | 75% | Model tuning, prompt engineering |
| QA Engineer | 1 | 50% | Testing, benchmarking |
| DevOps Engineer | 1 | 25% | CI/CD, infrastructure |
| Technical Writer | 1 | 25% | Documentation |

### Compute Resources

```
Development Environment:
├── GPU: 1x A100 40GB (local model testing)
├── RAM: 64GB minimum
├── Storage: 500GB SSD
└── Network: High bandwidth for API calls

CI/CD Infrastructure:
├── GitHub Actions runners (4 concurrent)
├── Test execution cluster (8 vCPU, 32GB RAM)
└── Artifact storage: 100GB

Production Deployment:
├── API endpoints for each agent
├── Rate limiting: 1000 requests/min per agent
└── Model caching layer (Redis)
```

### API Budget (Monthly)

| Provider | Agent Usage | Estimated Tokens | Cost |
|----------|-------------|------------------|------|
| OpenAI (GPT-4o) | Planner, Managers | 50M tokens | $500 |
| Anthropic (Claude) | Skeptics, Synthesizer | 30M tokens | $450 |
| Alias1 | Web3 BB, Critic | 100M tokens | $350 |
| **Total** | | | **$1,300/month** |

---

## Part 4: Integration Points

### 4.1 Existing System Integration Map

```
┌─────────────────────────────────────────────────────────────┐
│                    CAI Framework Core                        │
├─────────────────────────────────────────────────────────────┤
│  src/cai/                                                   │
│  ├── agents/                                                │
│  │   ├── __init__.py ←── Agent registry (MODIFY)           │
│  │   ├── factory.py ←── Agent factory (EXTEND)             │
│  │   └── patterns/ ←── Agentic patterns (ADD NEW)          │
│  │                                                          │
│  ├── tools/web3_security/                                   │
│  │   ├── enhancements/ ←── Reasoning tools (USE)           │
│  │   ├── protocols/ ←── Protocol analyzers (USE)           │
│  │   └── *.py ←── Security tools (USE)                     │
│  │                                                          │
│  ├── sdk/agents/                                            │
│  │   ├── Agent ←── Base class (INHERIT)                    │
│  │   ├── function_tool ←── Tool decorator (USE)            │
│  │   └── OpenAIChatCompletionsModel ←── Model (USE)        │
│  │                                                          │
│  └── repl/commands/                                         │
│      └── agent.py ←── CLI integration (EXTEND)             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Tool Integration Matrix

| Agent | Primary Tools | Secondary Tools |
|-------|--------------|-----------------|
| Skeptic Alpha | challenge_assumptions | attack_economics |
| Skeptic Beta | calculate_attack_profitability | exploit_scorer |
| Skeptic Gamma | slither_analyze, mythril_analyze | foundry |
| Critic | evaluate_finding | council_filter_findings |
| Planner | generate_plan, refine_plan | all manager tools |
| Exploit Synthesizer | generate_exploit_code | fork_test |
| PoC Generator | generate_poc | foundry |
| Manager Vuln | aggregate_tool_results | validate_finding |
| Manager Economic | analyze_defi_protocol | attack_economics |
| Manager Access | analyze_access_control | attack_graph |
| Attributor | trace_root_cause | correlator |
| Web3 Discovery | detect_web3_repo_context | repo_context |

### 4.3 Agent Communication Protocol

```python
# Agent handoff interface (src/cai/agents/patterns/web3_comprehensive.py)

class AgentMessage:
    sender: str          # Agent name
    recipient: str       # Target agent name
    message_type: str    # "finding", "request", "response", "handoff"
    payload: Dict        # Message content
    context: Dict        # Shared audit context
    priority: int        # 1-10 (10 = critical)
    
class AuditContext:
    target: str                    # Repository/contract path
    protocol_type: str             # "defi", "nft", "governance", "bridge"
    findings: List[Finding]        # Accumulated findings
    plan: AuditPlan               # Current execution plan
    tool_outputs: Dict[str, str]  # Cached tool results
```

---

## Part 5: Testing & Validation Procedures

### 5.1 Unit Testing Strategy

```
tests/
├── agents/
│   ├── test_skeptic_alpha.py
│   │   ├── test_challenge_assumptions_valid_input
│   │   ├── test_challenge_assumptions_invalid_input
│   │   ├── test_find_contradictions
│   │   └── test_verify_preconditions
│   ├── test_skeptic_beta.py
│   │   ├── test_profitability_calculation
│   │   ├── test_gas_estimation
│   │   └── test_mev_modeling
│   ├── test_critic.py
│   │   ├── test_three_dimensional_scoring
│   │   ├── test_threshold_filtering
│   │   └── test_verdict_generation
│   └── ... (one file per agent)
│
└── integration/
    ├── test_agent_handoffs.py
    ├── test_full_audit_flow.py
    └── test_multi_agent_coordination.py
```

### 5.2 Benchmark Integration

```python
# benchmarks/vuldetectbench/evaluate.py extension

AGENT_BENCHMARKS = {
    "skeptic_layer": {
        "dataset": "vuldetectbench/false_positives.json",
        "metric": "false_positive_rejection_rate",
        "target": 0.80  # 80% of false positives rejected
    },
    "critic_layer": {
        "dataset": "vuldetectbench/severity_calibration.json",
        "metric": "severity_correlation",
        "target": 0.85  # 85% correlation with human ratings
    },
    "synthesis_layer": {
        "dataset": "vuldetectbench/exploitable_vulns.json",
        "metric": "poc_success_rate",
        "target": 0.60  # 60% of true vulns get working PoC
    },
    "full_pipeline": {
        "dataset": "vuldetectbench/full_contracts.json",
        "metric": "f1_score",
        "target": 0.70  # F1 score on vulnerability detection
    }
}
```

### 5.3 Validation Checklist per Agent

```
Agent Validation Checklist:
□ Unit tests pass (100% coverage on critical paths)
□ Integration tests pass with adjacent agents
□ Benchmark targets met
□ Performance within latency budget (<30s per finding)
□ Token usage within budget
□ Error handling tested (malformed inputs, timeouts)
□ Logging and tracing functional
□ Documentation complete
□ Code review approved
□ Security review passed
```

---

## Part 6: Security Considerations

### 6.1 Threat Model

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Prompt Injection | Agent manipulation | Input sanitization, guardrails |
| Data Exfiltration | Sensitive code leak | Output filtering, rate limiting |
| Malicious Tool Output | False findings | Multi-agent verification |
| API Key Exposure | Unauthorized access | Environment variables, secrets management |
| Model Hallucination | False positives | Skeptic layer verification |
| Resource Exhaustion | DoS | Rate limiting, timeouts |

### 6.2 Security Controls

```python
# src/cai/agents/guardrails.py integration

AGENT_GUARDRAILS = {
    # Input guardrails
    "input_sanitization": True,
    "max_input_length": 500000,  # 500K chars
    "blocked_patterns": ["rm -rf", "sudo", "eval("],
    
    # Output guardrails
    "output_filtering": True,
    "redact_secrets": True,
    "max_output_length": 100000,
    
    # Execution guardrails
    "max_tool_calls_per_turn": 20,
    "timeout_per_tool": 300,  # 5 minutes
    "require_human_approval": ["deploy", "transfer", "execute"],
}
```

### 6.3 Risk Mitigation Matrix

| Risk | Likelihood | Impact | Mitigation | Owner |
|------|------------|--------|------------|-------|
| False positive flood | Medium | High | Skeptic layer + Critic | ML Engineer |
| Exploit code misuse | Low | Critical | Output filtering, usage logging | Security Lead |
| Model degradation | Medium | Medium | Benchmark regression testing | QA Engineer |
| API rate limiting | High | Low | Caching, request batching | Backend Engineer |
| Data privacy breach | Low | High | Input/output sanitization | Security Lead |

---

## Part 7: Performance Metrics & Success Criteria

### 7.1 Agent-Level Metrics

| Agent | Primary Metric | Target | Measurement Method |
|-------|---------------|--------|-------------------|
| Skeptic Alpha | FP Rejection Rate | ≥80% | vuldetectbench false_positives.json |
| Skeptic Beta | Economic Accuracy | ≥90% | Manual validation on 50 findings |
| Skeptic Gamma | Code Claim Accuracy | ≥95% | Bytecode verification tests |
| Critic | Severity Correlation | ≥0.85 | Spearman correlation with human ratings |
| Planner | Plan Completion Rate | ≥90% | Percentage of plans fully executed |
| Exploit Synthesizer | PoC Success Rate | ≥60% | Forge test pass rate |
| PoC Generator | Compilation Rate | ≥95% | Forge compile success |
| Manager Vuln | Coverage Score | ≥90% | Tool execution coverage |
| Manager Economic | Protocol Coverage | 100% | All DeFi patterns detected |
| Manager Access | Role Detection | ≥95% | Access control accuracy |
| Attributor | Root Cause Accuracy | ≥85% | Manual validation |
| Web3 Discovery | Context Detection | 100% | Framework/protocol identification |

### 7.2 System-Level Metrics

```
Overall Pipeline Metrics:
├── End-to-End Latency: <10 minutes per contract
├── False Positive Rate: <30%
├── True Positive Rate: >70%
├── F1 Score: >0.70
├── PoC Generation Rate: >50% of confirmed vulns
├── Token Efficiency: <$0.50 per contract analyzed
└── Availability: >99.5% uptime
```

### 7.3 Success Criteria by Milestone

| Milestone | Criteria | Verification |
|-----------|----------|--------------|
| M1: Core Orchestration | Planner generates valid plans | 50 test cases pass |
| M2: Adversarial Layer | FP reduction >50% | vuldetectbench comparison |
| M3: Coordination Layer | Multi-tool aggregation works | 100 contracts analyzed |
| M4: Synthesis Layer | PoC generation >40% | Known vuln reproduction |
| M5: Production Ready | All metrics met | Full benchmark suite |

### 7.4 Continuous Monitoring Dashboard

```
CAI Agent Health Dashboard:
┌────────────────────────────────────────────────────────┐
│ Agent Status              │ Last 24h │ 7-day Avg │ Target │
├───────────────────────────┼──────────┼───────────┼────────┤
│ Skeptic Alpha             │ ✓ 82%   │ 80%       │ 80%    │
│ Skeptic Beta              │ ✓ 91%   │ 89%       │ 90%    │
│ Skeptic Gamma             │ ✓ 96%   │ 95%       │ 95%    │
│ Critic                    │ ✓ 0.87  │ 0.86      │ 0.85   │
│ Planner                   │ ✓ 92%   │ 91%       │ 90%    │
│ Exploit Synthesizer       │ ⚠ 58%   │ 61%       │ 60%    │
│ PoC Generator             │ ✓ 97%   │ 96%       │ 95%    │
│ Manager Vuln              │ ✓ 93%   │ 92%       │ 90%    │
│ Manager Economic          │ ✓ 100%  │ 100%      │ 100%   │
│ Manager Access            │ ✓ 96%   │ 95%       │ 95%    │
│ Attributor                │ ✓ 87%   │ 86%       │ 85%    │
│ Web3 Discovery            │ ✓ 100%  │ 100%      │ 100%   │
├───────────────────────────┴──────────┴───────────┴────────┤
│ System F1: 0.72 │ Latency: 8.2min │ Cost: $0.42/contract │
└────────────────────────────────────────────────────────────┘
```

---

## Appendix A: File Structure

```
src/cai/agents/
├── __init__.py                    # Agent registry (UPDATE)
├── factory.py                     # Agent factory (EXTEND)
├── skeptic_alpha.py               # Logical denier (EXISTS)
├── skeptic_beta.py                # Economic checker (EXISTS)
├── skeptic_gamma.py               # Code verifier (EXISTS)
├── critic.py                      # GPTLens reviewer (EXISTS)
├── planner.py                     # Pre-Act planner (EXISTS)
├── exploit_synthesizer.py         # PoC synthesis (EXISTS)
├── poc_generator.py               # Foundry test gen (EXISTS)
├── manager_vuln.py                # Vuln coordinator (EXISTS)
├── manager_economic.py            # Economic coordinator (EXISTS)
├── manager_access.py              # Access coordinator (EXISTS)
├── attributor.py                  # Finding attribution (EXISTS)
├── web3_discovery_agent.py        # Recon agent (EXISTS)
├── patterns/
│   ├── web3_comprehensive.py      # Full audit pattern (EXISTS)
│   ├── adversarial.py             # Skeptic pattern (EXISTS)
│   └── ensemble.py                # Multi-agent pattern (EXISTS)
└── meta/
    └── reasoner_support.py        # Shared reasoning (EXISTS)
```

---

## Appendix B: Agent Interaction Diagram

```
                    ┌─────────────────┐
                    │  Web3 Discovery │
                    │      Agent      │
                    └────────┬────────┘
                             │ context
                             ▼
                    ┌─────────────────┐
                    │     Planner     │
                    │      Agent      │
                    └────────┬────────┘
                             │ plan
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │ Manager Vuln  │ │Manager Economic│ │ Manager Access │
    └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
            │                 │                 │
            └────────────────┬┴─────────────────┘
                             │ findings
                             ▼
            ┌────────────────────────────────────┐
            │          SKEPTIC LAYER             │
            │  ┌───────┐ ┌───────┐ ┌───────┐    │
            │  │ Alpha │ │ Beta  │ │ Gamma │    │
            │  └───┬───┘ └───┬───┘ └───┬───┘    │
            │      └─────────┼─────────┘        │
            └────────────────┼──────────────────┘
                             │ filtered findings
                             ▼
                    ┌─────────────────┐
                    │     Critic      │
                    │      Agent      │
                    └────────┬────────┘
                             │ accepted findings
                             ▼
                    ┌─────────────────┐
                    │   Attributor    │
                    └────────┬────────┘
                             │ attributed findings
                             ▼
            ┌────────────────────────────────────┐
            │       SYNTHESIS LAYER              │
            │  ┌──────────────┐ ┌─────────────┐  │
            │  │   Exploit    │ │    PoC      │  │
            │  │ Synthesizer  │ │  Generator  │  │
            │  └──────────────┘ └─────────────┘  │
            └────────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  FINAL REPORT   │
                    │  with working   │
                    │     PoCs        │
                    └─────────────────┘
```

---Based on my analysis of the CAI framework, here is the comprehensive implementation plan for the twelve cybersecurity AI agents:

---

# CAI Cybersecurity AI Agents - Implementation Plan

## Executive Summary

This document outlines the implementation plan for twelve specialized cybersecurity AI agents within the CAI framework. These agents form a coordinated system for comprehensive Web3 vulnerability detection, combining adversarial review, multi-step planning, and automated exploit synthesis.

---

## Agent Overview

| # | Agent | Role | Category |
|---|-------|------|----------|
| 1 | **Planner** | Multi-step audit planning (Pre-Act) | Orchestration |
| 2 | **Critic** | GPTLens-style adversarial review | Validation |
| 3 | **Skeptic Alpha** | Logical assumption denial | Adversarial |
| 4 | **Skeptic Beta** | Technical implementation denial | Adversarial |
| 5 | **Skeptic Gamma** | Economic viability denial | Adversarial |
| 6 | **Manager Vuln** | Vulnerability pattern management | Management |
| 7 | **Manager Economic** | Economic attack management | Management |
| 8 | **Manager Access** | Access control analysis | Management |
| 9 | **Exploit Synthesizer** | Attack path construction | Synthesis |
| 10 | **PoC Generator** | Foundry test generation | Synthesis |
| 11 | **Attributor** | Vulnerability classification | Analysis |
| 12 | **Web3 Orchestrator** | Master coordination agent | Orchestration |

---

## 1. Technical Requirements Per Agent

### Agent 1: Planner (`src/cai/agents/planner.py`)

**Purpose:** Generate comprehensive multi-step audit plans before execution (Pre-Act methodology)

**Technical Requirements:**
```python
# Core data structures
@dataclass
class PlanStep:
    step_number: int
    action: str                    # What to do
    agent: str                     # Which agent executes
    reasoning: str                 # Why this step
    expected_output: str           # What to expect
    depends_on: List[int]          # Dependencies
    status: StepStatus             # PENDING/IN_PROGRESS/COMPLETED/FAILED
    
@dataclass
class AuditPlan:
    goal: str
    target: str
    steps: List[PlanStep]
    current_step: int
```

**Required Tools:**
- `create_audit_plan(target, goal)` - Generate initial plan
- `refine_plan(plan, observation)` - Update plan based on results
- `get_next_step(plan)` - Get next executable step
- `mark_step_complete(plan, step_id, output)` - Record completion

**Dependencies:**
- `cai.sdk.agents.Agent`, `OpenAIChatCompletionsModel`
- `cai.tools.web3_security.detect_web3_repo_context`
- `cai.agents.factory.create_generic_agent_factory`

**Integration Points:**
- Receives audit targets from CLI/REPL via `--agent planner`
- Outputs plans consumed by `Web3 Orchestrator`
- Coordinates with all Manager agents for domain-specific planning

---

### Agent 2: Critic (`src/cai/agents/critic.py`)

**Purpose:** Evaluate findings on correctness, severity, and profitability (GPTLens methodology)

**Technical Requirements:**
```python
@dataclass
class CriticScore:
    correctness: float        # 0-10: Is reasoning logically sound?
    severity: float           # 0-10: How bad is actual impact?
    profitability: float      # 0-10: Would attacker bother?
    
    @property
    def passes_threshold(self) -> bool:
        return min(self.correctness, self.severity, self.profitability) >= 5.0

class Verdict(Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    NEEDS_MORE_INFO = "needs_more_info"
```

**Required Tools:**
- `evaluate_finding(finding)` - Score a finding
- `bulk_evaluate(findings)` - Score multiple findings
- `generate_rejection_report(finding, scores)` - Explain rejection
- `request_clarification(finding, missing_info)` - Request more data

**Dependencies:**
- Receives findings from `Manager Vuln`, `Manager Economic`, `Manager Access`
- Uses `cai.tools.web3_security.validate_finding` for cross-validation

**Integration Points:**
- All findings MUST pass Critic before final report
- Integrates with `benchmarks/vuldetectbench/evaluate.py` for accuracy measurement

---

### Agent 3: Skeptic Alpha (`src/cai/agents/skeptic_alpha.py`)

**Purpose:** Attack logical foundations of vulnerability claims

**Technical Requirements:**
```python
# Challenge tactics
LOGICAL_ATTACK_PATTERNS = {
    "assumption_chain_break": "Identify unstated assumptions",
    "contradiction_search": "Find internal logical contradictions",
    "missing_precondition": "Identify missing requirements",
    "circular_reasoning": "Detect self-referential logic",
    "causal_fallacy": "Challenge cause-effect relationships"
}
```

**Required Tools:**
- `challenge_assumptions(finding, stated_assumptions)` - Attack assumptions
- `find_contradictions(finding_set)` - Find internal contradictions
- `identify_missing_preconditions(finding)` - List unstated requirements
- `generate_counterexample(finding)` - Suggest disproving cases

**Integration Points:**
- Works in parallel with Skeptic Beta and Gamma
- Outputs feed into Critic for final verdict

---

### Agent 4: Skeptic Beta (`src/cai/agents/skeptic_beta.py`)

**Purpose:** Attack technical implementation claims

**Technical Requirements:**
```python
TECHNICAL_ATTACK_PATTERNS = {
    "code_path_unreachable": "Prove code path cannot be reached",
    "gas_limit_exceeded": "Show attack exceeds gas limits",
    "compiler_optimization": "Compiler eliminates vulnerability",
    "abi_encoding_mismatch": "ABI prevents exploitation",
    "evm_semantics": "EVM semantics prevent issue"
}
```

**Required Tools:**
- `verify_code_reachability(finding, call_graph)` - Check path exists
- `calculate_gas_cost(exploit_steps)` - Estimate total gas
- `check_compiler_behavior(code, version)` - Verify compiler output
- `validate_abi_compatibility(interfaces)` - Check ABI matching

**Dependencies:**
- `cai.tools.web3_security.slither_analyze` for call graph
- `cai.tools.web3_security.mythril_analyze` for path analysis

---

### Agent 5: Skeptic Gamma (`src/cai/agents/skeptic_gamma.py`)

**Purpose:** Attack economic viability of exploits

**Technical Requirements:**
```python
ECONOMIC_ATTACK_PATTERNS = {
    "unprofitable_attack": "Gas cost exceeds potential profit",
    "liquidity_insufficient": "Not enough liquidity to exploit",
    "flash_loan_unavailable": "Required flash loan not available",
    "mev_competition": "MEV bots would frontrun attacker",
    "slippage_protection": "Slippage makes attack unprofitable"
}

# Flash loan fee structures
FLASH_LOAN_PROVIDERS = {
    "aave": {"fee_percent": 0.09},
    "dydx": {"fee_percent": 0.0},
    "balancer": {"fee_percent": 0.0},
}
```

**Required Tools:**
- `calculate_attack_profitability(vector, value, operations)` - ROI calculation
- `estimate_mev_competition(block_data)` - MEV risk assessment
- `check_liquidity_depth(token, amount)` - Verify liquidity exists
- `simulate_slippage(trade_size, pool)` - Calculate actual slippage

**Dependencies:**
- `cai.tools.web3_security.enhancements.attack_economics`
- External: Tenderly/Foundry fork simulation

---

### Agent 6: Manager Vuln (`src/cai/agents/manager_vuln.py`)

**Purpose:** Coordinate vulnerability pattern detection and classification

**Technical Requirements:**
```python
VULNERABILITY_CATEGORIES = {
    "reentrancy": ["cross-function", "cross-contract", "read-only"],
    "access_control": ["missing-auth", "privilege-escalation", "centralization"],
    "oracle": ["manipulation", "staleness", "precision-loss"],
    "flash_loan": ["price-manipulation", "collateral-drain", "liquidation"],
    "upgrade": ["storage-collision", "initializer", "selfdestruct"]
}
```

**Required Tools:**
- `scan_for_patterns(target, categories)` - Run pattern detection
- `correlate_findings(tool_outputs)` - Combine multi-tool results
- `classify_finding(finding)` - Assign to category
- `prioritize_findings(findings)` - Rank by severity/exploitability

**Dependencies:**
- All static analysis tools: Slither, Mythril, Securify, Slitheryn
- `cai.tools.web3_security.enhancements.multi_tool_orchestrator`

---

### Agent 7: Manager Economic (`src/cai/agents/manager_economic.py`)

**Purpose:** Coordinate economic attack vector analysis

**Technical Requirements:**
```python
ECONOMIC_ATTACK_VECTORS = {
    "oracle_manipulation": ["spot_price", "twap_manipulation", "chainlink_staleness"],
    "flash_loan_attacks": ["arbitrage", "governance", "liquidation"],
    "mev_exposure": ["sandwich", "frontrun", "backrun", "jit_liquidity"],
    "price_impact": ["slippage", "donation", "inflation"]
}
```

**Required Tools:**
- `analyze_oracle_dependencies(target)` - Map oracle usage
- `detect_flash_loan_vectors(target)` - Find flash loan opportunities
- `calculate_mev_exposure(functions)` - Estimate MEV risk
- `simulate_economic_attack(vector, params)` - Run attack simulation

**Dependencies:**
- `cai.tools.web3_security.enhancements.defi_analyzer`
- `cai.tools.web3_security.enhancements.attack_economics`
- `cai.tools.web3_security.protocols.*` (AMM, Lending, Staking analyzers)

---

### Agent 8: Manager Access (`src/cai/agents/manager_access.py`)

**Purpose:** Coordinate access control and privilege analysis

**Technical Requirements:**
```python
ACCESS_CONTROL_PATTERNS = {
    "role_based": ["onlyOwner", "onlyAdmin", "hasRole"],
    "time_based": ["timelock", "delay", "cooldown"],
    "signature_based": ["ecrecover", "EIP712", "permit"],
    "proxy_based": ["transparent", "UUPS", "beacon", "diamond"]
}
```

**Required Tools:**
- `map_access_controls(target)` - Build access control graph
- `find_privilege_escalation(graph)` - Detect escalation paths
- `analyze_admin_keys(target)` - Identify centralization risks
- `check_upgrade_safety(proxy, impl)` - Validate upgrade patterns

**Dependencies:**
- `cai.tools.web3_security.slither_check_upgradeability`
- `cai.tools.web3_security.protocols.diamond_analyzer`

---

### Agent 9: Exploit Synthesizer (`src/cai/agents/exploit_synthesizer.py`)

**Purpose:** Construct working exploit paths from confirmed findings

**Technical Requirements:**
```python
EXPLOIT_PATTERNS = {
    "reentrancy": {
        "setup": "Deploy attacker contract with fallback",
        "exploit_steps": ["call_vulnerable", "reenter_in_fallback"],
        "assertion": "assert(stolen_amount > 0)"
    },
    "oracle_manipulation": {
        "setup": "Setup flash loan + DEX interaction",
        "exploit_steps": ["borrow", "manipulate_price", "exploit", "repay"],
        "assertion": "assert(profit > flash_loan_fee)"
    }
}
```

**Required Tools:**
- `synthesize_exploit(finding, pattern)` - Generate exploit code
- `build_attack_graph(findings)` - Construct multi-step paths
- `chain_exploits(exploits)` - Combine multiple vulnerabilities
- `validate_exploit_locally(code)` - Test in sandbox

**Dependencies:**
- `cai.tools.web3_security.foundry` for test execution
- `cai.tools.web3_security.fork_test` for mainnet forking
- `cai.tools.web3_security.enhancements.attack_graph`

---

### Agent 10: PoC Generator (`src/cai/agents/poc_generator.py`)

**Purpose:** Generate production-quality Foundry test files

**Technical Requirements:**
```python
POC_TEMPLATE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{contract_path}";

contract {test_name} is Test {
    {contract_type} target;
    address attacker = address(0xB33F);
    
    function setUp() public {
        {setup_code}
    }
    
    function testExploit() public {
        vm.startPrank(attacker);
        {exploit_code}
        vm.stopPrank();
        
        {assertions}
    }
}
"""
```

**Required Tools:**
- `generate_poc(finding, contract_code)` - Create test file
- `generate_setup_code(contracts, state)` - Create setUp function
- `generate_assertions(expected_impact)` - Create assert statements
- `compile_and_test(poc_code)` - Verify PoC compiles and runs

**Dependencies:**
- `cai.tools.web3_security.foundry.foundry_test`
- `cai.tools.web3_security.fork_test.generate_fork_test`

---

### Agent 11: Attributor (`src/cai/agents/attributor.py`)

**Purpose:** Classify vulnerabilities and map to known patterns/CVEs

**Technical Requirements:**
```python
TAXONOMY = {
    "SWC": {  # Smart Contract Weakness Classification
        "SWC-107": "Reentrancy",
        "SWC-100": "Function Default Visibility",
        "SWC-116": "Block Timestamp Dependency"
    },
    "DASP": {  # Decentralized Application Security Project
        "DASP-1": "Reentrancy",
        "DASP-2": "Access Control"
    }
}
```

**Required Tools:**
- `classify_finding(finding)` - Map to SWC/DASP
- `find_similar_exploits(finding)` - Search exploit DB
- `generate_cwe_mapping(finding)` - Map to CWE
- `estimate_cvss_score(finding)` - Calculate severity score

**Dependencies:**
- `cai.tools.web3_security.taxonomy`
- `cai.tools.web3_security.knowledge_base`
- External exploit databases (DeFiHackLabs, Rekt News)

---

### Agent 12: Web3 Orchestrator (`src/cai/agents/web3_bug_bounty.py`)

**Purpose:** Master coordination agent for complete audit workflow

**Technical Requirements:**
```python
AUDIT_PHASES = [
    "discovery",      # Repo context, architecture mapping
    "static",         # Slither, Mythril, Securify
    "dynamic",        # Echidna, Medusa fuzzing
    "formal",         # Certora, Scribble verification
    "adversarial",    # Skeptic review
    "synthesis",      # Exploit generation
    "validation",     # PoC testing
    "reporting"       # Final report
]
```

**Required Tools:**
- All tools from Manager agents
- `run_audit_phase(phase, target)` - Execute audit phase
- `coordinate_agents(agents, task)` - Dispatch to sub-agents
- `aggregate_results(phase_outputs)` - Combine all findings
- `generate_final_report(validated_findings)` - Create audit report

**Integration Points:**
- Entry point via `cai --agent web3_bug_bounty`
- Coordinates all 11 other agents
- Outputs to `cai.tools.web3_security.auditor_generate_report`

---

## 2. Implementation Timeline

### Phase 1: Foundation (Weeks 1-3)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M1.1 | Core agent base class extensions | All |
| M1.2 | Factory pattern integration | All |
| M1.3 | Inter-agent communication protocol | All |

**Key Activities:**
- Extend `cai.agents.factory.create_generic_agent_factory` for new agents
- Define standard message formats for agent-to-agent communication
- Create shared data structures (`Finding`, `Plan`, `Score`)

### Phase 2: Orchestration Layer (Weeks 4-6)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M2.1 | Planner agent complete | Planner |
| M2.2 | Web3 Orchestrator skeleton | Orchestrator |
| M2.3 | Agent handoff protocol | All |

**Key Activities:**
- Implement Pre-Act planning methodology
- Create audit phase state machine
- Build agent dispatch and result collection

### Phase 3: Management Layer (Weeks 7-10)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M3.1 | Manager Vuln complete | Manager Vuln |
| M3.2 | Manager Economic complete | Manager Economic |
| M3.3 | Manager Access complete | Manager Access |
| M3.4 | Cross-manager correlation | All Managers |

**Key Activities:**
- Integrate existing web3_security tools
- Build finding correlation logic
- Create unified finding schema

### Phase 4: Adversarial Layer (Weeks 11-14)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M4.1 | Critic agent complete | Critic |
| M4.2 | Skeptic Alpha complete | Skeptic Alpha |
| M4.3 | Skeptic Beta complete | Skeptic Beta |
| M4.4 | Skeptic Gamma complete | Skeptic Gamma |
| M4.5 | Adversarial ensemble | All Skeptics |

**Key Activities:**
- Implement GPTLens scoring methodology
- Create parallel skeptic execution
- Build consensus mechanism for rejection

### Phase 5: Synthesis Layer (Weeks 15-18)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M5.1 | Exploit Synthesizer complete | Exploit Synthesizer |
| M5.2 | PoC Generator complete | PoC Generator |
| M5.3 | Attributor complete | Attributor |
| M5.4 | End-to-end exploit pipeline | All Synthesis |

**Key Activities:**
- Integrate Foundry test generation
- Build mainnet fork testing
- Create exploit DB integration

### Phase 6: Integration & Testing (Weeks 19-22)

| Milestone | Deliverables | Agents |
|-----------|-------------|--------|
| M6.1 | Full system integration | All |
| M6.2 | Benchmark evaluation | All |
| M6.3 | Performance optimization | All |
| M6.4 | Documentation complete | All |

---

## 3. Resource Allocation & Dependencies

### Development Resources

| Agent Category | Estimated Effort | Complexity |
|---------------|------------------|------------|
| Orchestration (2) | 6 weeks | High |
| Management (3) | 8 weeks | Medium |
| Adversarial (4) | 8 weeks | High |
| Synthesis (3) | 8 weeks | High |
| **Total** | **22 weeks** | - |

### External Dependencies

```
┌─────────────────────────────────────────────────────────────┐
│                     CAI Agent System                        │
├─────────────────────────────────────────────────────────────┤
│  Internal Dependencies                                      │
│  ├── cai.sdk.agents (Agent, OpenAIChatCompletionsModel)    │
│  ├── cai.agents.factory (create_generic_agent_factory)     │
│  ├── cai.tools.web3_security.* (50+ tools)                 │
│  └── cai.tools.common.run_command                          │
├─────────────────────────────────────────────────────────────┤
│  External Tool Dependencies                                 │
│  ├── Slither (static analysis)                             │
│  ├── Mythril (symbolic execution)                          │
│  ├── Foundry (testing/forking)                             │
│  ├── Echidna/Medusa (fuzzing)                              │
│  └── Certora (formal verification)                         │
├─────────────────────────────────────────────────────────────┤
│  API Dependencies                                           │
│  ├── OpenAI API (GPT-4/GPT-4o)                             │
│  ├── Anthropic API (Claude)                                │
│  ├── Alias API (alias1 model)                              │
│  └── Etherscan API (on-chain data)                         │
└─────────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
                    ┌──────────────────┐
                    │  Web3 Orchestrator │
                    └────────┬─────────┘
                             │
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
    ┌──────────┐      ┌──────────┐      ┌──────────┐
    │ Planner  │      │ Managers │      │ Attributor│
    └────┬─────┘      └────┬─────┘      └──────────┘
         │                 │
         │    ┌────────────┼────────────┐
         ▼    ▼            ▼            ▼
    ┌─────────────┐  ┌──────────┐  ┌──────────┐
    │   Critic    │  │ Skeptics │  │ Synthesizers│
    └─────────────┘  └──────────┘  └──────────┘
```

---

## 4. Integration Points

### 4.1 CLI/REPL Integration

```python
# src/cai/repl/commands/agent.py
AGENT_COMMANDS = {
    "planner": "Start audit planning session",
    "audit": "Run full orchestrated audit",
    "skeptic": "Run adversarial review on findings",
    "synthesize": "Generate PoC for finding"
}

# Usage examples
# cai --agent planner --target ./contracts/
# cai --agent web3_orchestrator --target ./protocol/ --phases static,adversarial
```

### 4.2 agents.yml Configuration

```yaml
# agents.yml - Parallel agent configuration
parallel_agents:
  - name: manager_vuln
    prompt: "Scan for vulnerability patterns in {target}"
    unified_context: false
    
  - name: manager_economic
    prompt: "Analyze economic attack vectors in {target}"
    unified_context: false
    
  - name: manager_access
    prompt: "Map access control and privilege paths in {target}"
    unified_context: false

# Sequential adversarial review
sequential_agents:
  - name: skeptic_alpha
    depends_on: [manager_vuln, manager_economic, manager_access]
    
  - name: skeptic_beta
    depends_on: [skeptic_alpha]
    
  - name: skeptic_gamma
    depends_on: [skeptic_beta]
    
  - name: critic
    depends_on: [skeptic_gamma]
```

### 4.3 Pattern Integration

```python
# src/cai/agents/patterns/aegis_ensemble.py
from cai.agents.patterns.pattern import Pattern, PatternType

aegis_ensemble = Pattern(
    name="aegis_ensemble",
    type=PatternType.SWARM,
    description="Coordinated multi-agent audit with adversarial review",
    entry_agent=web3_orchestrator,
    agents=[
        planner, critic,
        skeptic_alpha, skeptic_beta, skeptic_gamma,
        manager_vuln, manager_economic, manager_access,
        exploit_synthesizer, poc_generator, attributor
    ],
    handoff_rules={
        "planner": ["manager_vuln", "manager_economic", "manager_access"],
        "manager_*": ["critic", "skeptic_alpha"],
        "skeptic_gamma": ["exploit_synthesizer"],
        "exploit_synthesizer": ["poc_generator"]
    }
)
```

### 4.4 MCP Tool Integration

```python
# Factory MCP tool injection (already implemented)
def factory(model_override=None, custom_name=None, agent_id=None):
    # ... agent creation ...
    
    # Auto-inject MCP tools for agent
    mcp_tools = get_mcp_tools_for_agent(agent_var_name)
    if mcp_tools:
        cloned_agent.tools.extend(mcp_tools)
```

---

## 5. Testing & Validation Procedures

### 5.1 Unit Testing Framework

```python
# tests/agents/test_planner.py
import pytest
from cai.agents.planner import planner, create_audit_plan

class TestPlanner:
    def test_plan_creation(self):
        plan = create_audit_plan(
            target="./test_contracts/",
            goal="Find reentrancy vulnerabilities"
        )
        assert len(plan.steps) > 0
        assert plan.steps[0].status == StepStatus.PENDING
        
    def test_plan_refinement(self):
        plan = create_audit_plan(...)
        refined = refine_plan(plan, "Slither found 3 issues")
        assert refined.current_step > plan.current_step
```

### 5.2 Integration Testing

```python
# tests/agents/test_ensemble.py
class TestAegisEnsemble:
    @pytest.fixture
    def sample_contract(self):
        return Path("tests/fixtures/vulnerable_vault.sol")
    
    async def test_full_audit_pipeline(self, sample_contract):
        # Run orchestrated audit
        result = await run_orchestrated_audit(
            target=sample_contract,
            phases=["static", "adversarial", "synthesis"]
        )
        
        # Verify findings were generated
        assert len(result.findings) > 0
        
        # Verify adversarial review occurred
        assert all(f.critic_score is not None for f in result.findings)
        
        # Verify PoC was generated for high-severity
        high_severity = [f for f in result.findings if f.severity >= 8]
        assert all(f.poc_code is not None for f in high_severity)
```

### 5.3 Benchmark Integration

```python
# benchmarks/aegis_eval.py
"""
Evaluate Aegis agents against known vulnerability datasets.

Datasets:
- SmartBugs (142 vulnerable contracts)
- DeFiHackLabs (200+ real exploits)
- SWC Registry (100+ patterns)
"""

def evaluate_agent_ensemble(dataset_path: str):
    results = {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 0.0,
        "recall": 0.0,
        "f1_score": 0.0
    }
    
    for contract, ground_truth in load_dataset(dataset_path):
        findings = run_full_audit(contract)
        validated = run_adversarial_review(findings)
        
        # Compare against ground truth
        results = update_metrics(results, validated, ground_truth)
    
    return results
```

### 5.4 Validation Checklist

| Validation | Method | Pass Criteria |
|------------|--------|---------------|
| Finding accuracy | Benchmark eval | F1 >= 0.70 |
| False positive rate | Adversarial review | FP rate <= 20% |
| PoC compilation | Foundry compile | 100% compile |
| PoC execution | Foundry test | >= 80% pass |
| Critic consistency | Inter-rater reliability | Kappa >= 0.75 |
| Plan coverage | Step completion | >= 90% completed |

---

## 6. Security Considerations & Risk Mitigation

### 6.1 Prompt Injection Defense

```python
# src/cai/agents/guardrails.py
AGENT_GUARDRAILS = {
    "input_sanitization": {
        "enabled": True,
        "patterns": [
            r"ignore previous instructions",
            r"system prompt",
            r"reveal.*instructions"
        ]
    },
    "output_validation": {
        "enabled": True,
        "dangerous_patterns": [
            r"rm\s+-rf",
            r"curl.*\|.*sh",
            r"eval\("
        ]
    }
}

@input_guardrail
async def check_prompt_injection(input_text: str) -> bool:
    for pattern in GUARDRAILS["input_sanitization"]["patterns"]:
        if re.search(pattern, input_text, re.IGNORECASE):
            raise GuardrailTripwireTriggered("Potential prompt injection detected")
    return True
```

### 6.2 Code Execution Sandboxing

```python
# PoC execution in isolated environment
POC_EXECUTION_CONFIG = {
    "sandbox": True,
    "network": "isolated",  # No external network access
    "timeout": 300,         # 5 minute max execution
    "resource_limits": {
        "memory": "2GB",
        "cpu": "2 cores"
    },
    "allowed_commands": [
        "forge test",
        "forge build"
    ]
}
```

### 6.3 Data Handling

| Data Type | Handling | Storage |
|-----------|----------|---------|
| Contract source | Read-only | Temporary |
| API keys | Environment vars | Never logged |
| Findings | Encrypted at rest | Local only |
| PoC code | Sandboxed execution | Temp directory |

### 6.4 Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Prompt injection | Medium | High | Input guardrails + output validation |
| Malicious PoC execution | Low | Critical | Sandbox + resource limits |
| API key exposure | Low | High | Environment isolation |
| False positive floods | Medium | Medium | Adversarial review layer |
| Agent hallucination | High | Medium | Multi-agent consensus |

---

## 7. Performance Metrics & Success Criteria

### 7.1 Detection Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Precision** | >= 80% | TP / (TP + FP) |
| **Recall** | >= 70% | TP / (TP + FN) |
| **F1 Score** | >= 0.75 | 2 * (P * R) / (P + R) |
| **False Positive Rate** | <= 20% | FP / (FP + TN) |

### 7.2 Operational Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Audit completion time** | < 30 min/contract | Wall clock time |
| **Agent response latency** | < 10s p95 | API response time |
| **PoC generation rate** | >= 80% | PoC generated / high-sev findings |
| **PoC compilation rate** | 100% | Compiled / generated |
| **PoC execution pass rate** | >= 80% | Tests passed / executed |

### 7.3 Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Critic agreement rate** | >= 85% | Human-Critic alignment |
| **Skeptic rejection accuracy** | >= 90% | True rejections / total rejections |
| **Plan completion rate** | >= 95% | Steps completed / planned |
| **Report actionability** | >= 90% | Findings with clear remediation |

### 7.4 Benchmark Targets

```python
# Expected performance on standard benchmarks
BENCHMARK_TARGETS = {
    "smartbugs_curated": {
        "precision": 0.85,
        "recall": 0.75,
        "f1": 0.80
    },
    "defihacklabs": {
        "detection_rate": 0.70,  # Detect known exploits
        "poc_generation": 0.60  # Generate working PoC
    },
    "swc_registry": {
        "coverage": 0.90  # Detect 90% of SWC patterns
    }
}
```

### 7.5 Success Criteria Summary

The implementation is considered successful when:

1. **Detection Quality**: F1 score >= 0.75 on SmartBugs benchmark
2. **False Positive Control**: <= 20% FP rate after adversarial review
3. **PoC Quality**: >= 80% of high-severity findings have working PoCs
4. **Operational Efficiency**: Full audit completes in < 30 minutes
5. **Integration**: All 12 agents successfully coordinate via Orchestrator
6. **Reliability**: >= 95% uptime with graceful degradation

---

## Appendix A: File Structure

```
src/cai/agents/
├── __init__.py                    # Agent registry
├── factory.py                     # Generic agent factory
├── guardrails.py                  # Security guardrails
│
├── # Orchestration Layer
├── planner.py                     # Pre-Act planning
├── web3_bug_bounty.py             # Master orchestrator
│
├── # Management Layer
├── manager_vuln.py                # Vulnerability management
├── manager_economic.py            # Economic attack management
├── manager_access.py              # Access control management
│
├── # Adversarial Layer
├── critic.py                      # GPTLens-style review
├── skeptic_alpha.py               # Logical denial
├── skeptic_beta.py                # Technical denial
├── skeptic_gamma.py               # Economic denial
│
├── # Synthesis Layer
├── exploit_synthesizer.py         # Attack path construction
├── poc_generator.py               # Foundry test generation
├── attributor.py                  # Vulnerability classification
│
└── patterns/
    ├── __init__.py
    ├── pattern.py                 # Pattern base class
    ├── ensemble.py                # Multi-agent ensembles
    └── aegis_ensemble.py          # Aegis-specific pattern
```

---

## Appendix B: Agent Communication Protocol

```python
# Standard message format for inter-agent communication
@dataclass
class AgentMessage:
    sender: str           # Agent name
    recipient: str        # Target agent
    message_type: str     # "finding", "score", "plan_step", "rejection"
    payload: Dict[str, Any]
    timestamp: datetime
    correlation_id: str   # For tracking related messages

# Example finding message
finding_msg = AgentMessage(
    sender="manager_vuln",
    recipient="critic",
    message_type="finding",
    payload={
        "finding_id": "VUL-001",
        "type": "reentrancy",
        "severity": 8,
        "description": "Cross-function reentrancy in withdraw()",
        "evidence": {"file": "Vault.sol", "line": 142}
    },
    timestamp=datetime.now(),
    correlation_id="audit-2024-001"
)
```

---

This implementation plan provides a comprehensive roadmap for building the twelve-agent CAI cybersecurity system. The modular architecture allows for incremental development while maintaining clear integration points and measurable success criteria.

Now I have a comprehensive understanding of the project structure. Let me create the detailed to-do list:Now I'll create the comprehensive project to-do list and implementation plan. Let me write this as a structured document:
Now let me create the documentation structure and implement the key missing components:
Now let me create integration tests for the agent ensemble and then add a Web3 audit workflow example:
I've created a comprehensive to-do list and implemented several key components. Here's a summary of what was accomplished:

---

## Implementation Summary

### Files Created

| File | Description |
|------|-------------|
| `PROJECT_TODO.md` | Comprehensive 131-task project to-do list |
| `docs/agents/web3/overview.md` | Web3 Security Agents documentation |
| `src/cai/agents/bridge_analyzer.py` | Bridge/Cross-chain Analyzer agent (P0) |
| `src/cai/agents/mev_analyzer.py` | MEV Vulnerability Analyzer agent (P0) |
| `tests/agents/web3/test_bridge_analyzer.py` | Unit tests for Bridge Analyzer |
| `tests/agents/web3/test_mev_analyzer.py` | Unit tests for MEV Analyzer |
| `tests/agents/web3/test_aegis_integration.py` | Integration tests for agent ensemble |
| `tests/agents/web3/__init__.py` | Test package init |
| `examples/web3_security/audit_workflow.py` | Web3 audit workflow example |

### Files Modified

| File | Change |
|------|--------|
| `src/cai/agents/__init__.py` | Added `bridge_analyzer` and `mev_analyzer` to registry |

### Completed Tasks

| Category | Task | Priority |
|----------|------|----------|
| CODE | Bridge/Cross-chain Analyzer agent | P0 |
| CODE | MEV Analysis agent | P0 |
| CODE | Review Skeptic Beta (already complete) | P1 |
| CODE | Review Skeptic Gamma (already complete) | P1 |
| DOCS | Web3 Security Agents overview | P1 |
| TEST | Unit tests for new analyzers | P1 |
| TEST | Integration tests for ensemble | P1 |
| EXAMPLES | Web3 audit workflow example | P1 |

### Remaining Tasks (by priority)

**P1 - High Priority:**
- SmartBugs benchmark integration
- Aegis evaluation metrics
- API reference updates for 12 agents

**P2 - Medium Priority:**
- Additional protocol analyzers (perpetuals, options, stablecoin)
- Account Abstraction (EIP-4337) tools
- Restaking protocol tools
- Additional MCP integrations

### New Agent Capabilities

**Bridge Analyzer:**
- Replay protection analysis
- Signature verification security
- Message validation checks
- Validator security assessment
- Known exploit pattern matching (Ronin, Wormhole, Nomad, Harmony)

**MEV Analyzer:**
- Sandwich attack vulnerability detection
- Frontrunning vulnerability analysis
- Backrunning opportunity detection
- MEV exposure calculation
- Mitigation recommendations

The project to-do document `PROJECT_TODO.md` contains the full 131-task breakdown across all categories with priorities and dependencies.

------------------------------------------


Continuing with the implementation of remaining protocol analyzers. Let me first check what was created in the previous session and then continue with the pending tasks.
Let me check the current project structure to understand what exists:
Let me check the src directory structure and existing agents:
Good, I can see the previous work was persisted. Let me verify what was created and continue with the remaining implementations:
Let me check what was completed from the previous session and update the task list:
Let me update the todo list to reflect current progress and continue implementing:Continuing implementation of protocol analyzers. First, let me register the perpetuals_analyzer and then implement the remaining analyzers.
(upgrade required)