# Aegis Integration - Research-Backed Web3 Security Patterns

This document describes the Aegis capabilities integrated into CAI, including research-backed multi-agent patterns that significantly improve vulnerability detection accuracy.

## Overview

CAI now includes specialized Web3 security auditing patterns from Aegis, implementing research findings from leading security papers:

| Feature | Research Paper | Improvement |
|---------|----------------|-------------|
| **HMAW Pattern** | "Towards Hierarchical Multi-Agent Workflows" | 30.7% improvement over baseline |
| **Adversarial Pattern** | GPTLens paper | 33.3% → 59.0% accuracy |
| **IRIS Integration** | "IRIS: LLM-ASSISTED STATIC ANALYSIS" | 103.7% improvement |
| **Ensemble Voting** | LLMBugScanner | 60% top-5 detection accuracy |

## Multi-Agent Patterns

### 1. HMAW (Hierarchical Multi-Agent Workflow)

A three-layer hierarchy with skip connections that preserves context:

```
CEO (Orchestrator)
    ├── Vulnerability Manager → Workers
    ├── Economic Manager → Workers
    └── Access Control Manager → Workers
```

**Key Features:**
- Skip connections pass original query to all layers (prevents information loss)
- Parallel execution at manager and worker levels
- Domain-specific managers for focused analysis

**Usage:**
```python
from cai.agents.patterns import hmaw_pattern

pattern = hmaw_pattern(
    name="web3_audit_hmaw",
    ceo=orchestrator_agent,
    managers={
        "vulnerability": manager_vuln,
        "economic": manager_economic,
        "access": manager_access
    },
    workers={
        "vulnerability": [static_analyzer, fuzzing_specialist],
        "economic": [mev_analyzer, flash_loan_analyzer],
        "access": [permission_checker, upgrade_analyzer]
    }
)

results = await pattern.execute("audit target.sol")
```

**Configuration:**
```bash
CAI_PATTERN="hmaw"
```

### 2. Adversarial Pattern (GPTLens)

Separates generation (auditors) from discrimination (critics):

**Phase 1 - Auditors (High Recall):**
- Multiple auditors with high temperature (0.8)
- Generate diverse vulnerability candidates
- Focus on recall, not precision

**Phase 2 - Critics (High Precision):**
- Evaluate findings on three dimensions:
  - Correctness (logical soundness)
  - Severity (actual impact)
  - Profitability (economic viability)
- Consensus voting (60% threshold)

**Usage:**
```python
from cai.agents.patterns import adversarial_pattern

pattern = adversarial_pattern(
    name="web3_audit_adversarial",
    auditors=[auditor1, auditor2, auditor3],
    critics=[skeptic_alpha, skeptic_beta, skeptic_gamma],
    auditor_temperature=0.8,
    min_critic_score=5.0,
    require_consensus=True
)

results = await pattern.execute("target.sol")
```

**Configuration:**
```bash
CAI_PATTERN="adversarial"
CAI_SKEPTIC_LEVEL="high"  # Aggressiveness of critics
```

### 3. Ensemble Pattern (LLMBugScanner)

Multi-model consensus voting for robust detection:

**Voting Methods:**
1. **Weighted Majority** - Higher-performing agents get higher weights
2. **Permutation-Optimized** - Learned priority for tie-breaking
3. **Unanimous** - All agents must agree (highest precision)
4. **Simple Majority** - One agent, one vote

**Usage:**
```python
from cai.agents.patterns import ensemble_pattern, VotingMethod

pattern = ensemble_pattern(
    name="web3_audit_ensemble",
    agents=[agent1, agent2, agent3],
    voting=VotingMethod.WEIGHTED_MAJORITY,
    weights={"agent1": 1.2, "agent2": 1.0, "agent3": 0.8},
    min_agreement=0.3,
    top_k=5
)

results = await pattern.execute("target.sol")
```

**Configuration:**
```bash
CAI_PATTERN="ensemble"
CAI_ENSEMBLE_VOTING="weighted"  # or permutation, unanimous, simple
```

## Specialized Agents

### Skeptic Agents (Adversarial Review)

**Skeptic Alpha - Logical Denier:**
- Attacks logical foundations of vulnerability claims
- Breaks assumption chains
- Finds contradictions and reasoning flaws
- Tools: `challenge_assumptions`, `find_logical_flaws`, `verify_causal_chain`

**Skeptic Beta - Economic Executioner:**
- Proves attacks economically impossible or irrational
- Calculates attack costs and profits
- Analyzes ROI and MEV competition
- Tools: `calculate_attack_cost`, `estimate_attack_profit`, `analyze_roi`

**Skeptic Gamma - Defense Analyst:**
- Exposes protective mechanisms that block attacks
- Finds access controls, input validation, reentrancy guards
- Identifies rate limiting and emergency stops
- Tools: `find_access_controls`, `find_reentrancy_guards`, `find_emergency_stops`

### HMAW Manager Agents

**Vulnerability Manager:**
- Coordinates vulnerability-focused analysis
- Generates hypotheses for workers to test
- Synthesizes findings across vulnerability domains

**Economic Manager:**
- Coordinates economic attack analysis
- Calculates ROI for attack scenarios
- Prioritizes by economic viability

**Access Control Manager:**
- Coordinates permission and access analysis
- Builds access control matrix
- Maps privilege escalation paths

## Pivot Engine (Grit Mode)

Hypothesis-driven persistence that ensures exhaustive exploration:

**Features:**
- Tracks attack hypotheses with status (pending, confirmed, disproven)
- Detects when stuck (no high-confidence findings)
- Suggests pivot strategies:
  - **Invert Assumption** - Attack the opposite of what was assumed safe
  - **Zoom In** - Deep dive on one suspicious function
  - **Switch Modality** - Change analysis approach (static → fuzz → symbolic)
  - **Explore Edges** - Focus on contract interaction boundaries

**Usage:**
```python
from cai.agents.pivot_engine import (
    pivot_engine_init,
    pivot_engine_add_hypothesis,
    pivot_engine_check_stuck,
    pivot_engine_exhaustion_proof
)

# Initialize
pivot_engine_init(max_attempts=10, stuck_threshold=3)

# Add hypothesis
pivot_engine_add_hypothesis(
    hypothesis="First depositor can inflate share price",
    evidence_for="No virtual offset in vault",
    evidence_against="Might have minimum deposit requirement"
)

# Check if stuck
status = pivot_engine_check_stuck()

# Generate exhaustion proof when done
proof = pivot_engine_exhaustion_proof()
```

**Configuration:**
```bash
CAI_GRIT_MODE="true"
CAI_STUCK_THRESHOLD="3"
CAI_MAX_HYPOTHESES="10"
```

## IRIS Neuro-Symbolic Integration

Combines LLM reasoning with static analysis for improved detection:

**Three-Phase Process:**

1. **LLM Infers Taint Specs** - Identifies sources, sinks, propagators
2. **Static Analysis with Specs** - Runs Slither with LLM-inferred specs
3. **Contextual Filtering** - LLM filters false positives

**Tools:**
- `iris_infer_taint_specs` - Phase 1: Infer specifications
- `iris_enhanced_slither_analysis` - Phase 2: Run enhanced Slither
- `iris_contextual_filter` - Phase 3: Filter false positives
- `iris_batch_contextual_filter` - Batch filtering for multiple findings

**Usage:**
```python
# Phase 1: Infer taint specs
specs = iris_infer_taint_specs(contract_code, contract_name)

# Phase 2: Run Slither with specs
analysis = iris_enhanced_slither_analysis(target_path, specs)

# Phase 3: Filter findings
for finding in slither_results:
    verdict = iris_contextual_filter(
        finding_description=finding["description"],
        source_code=finding["source_context"],
        sink_code=finding["sink_context"]
    )
```

## Enhancement Tools

### Attack Economics
Economic viability analysis for exploits:
- Cost calculation (gas, flash loan fees, capital)
- Profit estimation (TVL, extraction rate, slippage)
- ROI analysis
- MEV competition assessment

### Precision Analysis
Detects precision loss vulnerabilities:
- Rounding errors in division
- Share price manipulation
- Donation attacks

### Timing Analysis
Race condition and timing attack detection:
- Block timestamp dependencies
- Transaction ordering issues
- Frontrunning opportunities

### Invariant Generation
Automated invariant generation for formal verification:
- State invariants
- Relationship invariants
- Economic invariants

### DeFi Analyzer
Protocol-specific analysis:
- AMM analysis (Uniswap, Curve, Balancer)
- Lending protocol analysis (Aave, Compound)
- Yield vault analysis (ERC4626)

## Protocol Analyzers

### ERC4626 Analyzer
Vault-specific vulnerability detection:
- First depositor attacks
- Inflation attacks
- Share price manipulation
- Donation attacks
- Reentrancy via callbacks

### Diamond Analyzer
Diamond pattern security analysis:
- Facet collision detection
- Storage collision risks
- Upgrade path validation
- Selector conflicts

## Autonomous Audit Coordinator

Intelligent, adaptive audit system that:

**Capabilities:**
1. **Project Characterization** - Detects protocol types (vault, AMM, lending, etc.)
2. **Hypothesis Generation** - Creates attack hypotheses based on characteristics
3. **Tool Prioritization** - Selects optimal tools for detected patterns
4. **Deep Dive Decisions** - Automatically investigates critical findings
5. **Pivot Logic** - Changes approach when stuck
6. **Exhaustion Proof** - Documents complete coverage when no exploits found

**Usage:**
```python
from cai.tools.web3_security.audit_autonomous import (
    create_coordinator,
    AutonomousAuditCoordinator
)

# Create coordinator
coordinator = create_coordinator(
    project_path=Path("./contracts"),
    output_dir=Path("./audit_results")
)

# Analyze project
characteristics = await coordinator.analyze_project_characteristics(contract_files)

# Generate hypotheses
hypotheses = coordinator.generate_hypotheses()

# Prioritize tools
tools = coordinator.prioritize_tools()

# Check if should pivot
should_pivot, reason, direction = coordinator.should_pivot()

# Generate exhaustion proof
proof = coordinator.generate_exhaustion_proof()
```

## Environment Variables

```bash
# Pattern Selection
CAI_PATTERN="swarm"                    # swarm, parallel, hmaw, adversarial, ensemble

# Adversarial Pattern Configuration
CAI_SKEPTIC_LEVEL="medium"             # low, medium, high
CAI_AUDITOR_TEMPERATURE="0.8"          # 0.0-1.0 (higher = more diverse findings)
CAI_MIN_CRITIC_SCORE="5.0"             # 0-10 threshold
CAI_CONSENSUS_THRESHOLD="0.6"          # 0-1 (60% of critics must agree)

# Ensemble Pattern Configuration
CAI_ENSEMBLE_VOTING="weighted"         # weighted, permutation, unanimous, simple
CAI_MIN_AGREEMENT="0.3"                # 0-1 (30% of agents must agree)
CAI_TOP_K="5"                          # Number of top findings to return

# HMAW Pattern Configuration
CAI_SKIP_CONNECTIONS="true"            # Enable skip connections (recommended)
CAI_PARALLEL_MANAGERS="true"           # Run managers in parallel
CAI_PARALLEL_WORKERS="true"            # Run workers in parallel

# Pivot Engine (Grit Mode)
CAI_GRIT_MODE="true"                   # Enable hypothesis tracking
CAI_STUCK_THRESHOLD="3"                # Tools without findings before pivoting
CAI_MAX_HYPOTHESES="10"                # Maximum hypotheses to track

# Planning
CAI_PLANNING_DEPTH="3"                 # 1-5 (depth of Pre-Act planning)
```

## Research Citations

1. **HMAW:** "Towards Hierarchical Multi-Agent Workflows for Zero-Shot Prompt Optimization"
2. **GPTLens:** "Large Language Model-Powered Smart Contract Vulnerability Detection: New Perspectives"
3. **IRIS:** "IRIS: LLM-ASSISTED STATIC ANALYSIS FOR DETECTING SECURITY VULNERABILITIES"
4. **LLMBugScanner:** "Large Language Model based Smart Contract Auditing with LLMBugScanner"

## Migration from Aegis

If migrating from standalone Aegis:

1. **State Files:** `~/.aegis/` → `~/.cai/`
2. **Environment Prefix:** `AEGIS_` → `CAI_`
3. **Import Paths:** `from aegis.` → `from cai.`
4. **MCP Config:** `.aegis/mcp.json` → Uses standard CAI configuration

## Best Practices

### When to Use Each Pattern

**HMAW:**
- Large protocols requiring domain-specific expertise
- When you need systematic coverage across multiple domains
- Complex multi-contract systems

**Adversarial:**
- When precision is critical (minimize false positives)
- High-stakes audits requiring rigorous validation
- When you have time for multi-phase analysis

**Ensemble:**
- When using multiple LLM models
- To reduce false positives through consensus
- For critical findings requiring high confidence

**Swarm (default):**
- Most general-purpose audits
- When you want flexibility in agent handoffs
- Dynamic, exploratory analysis

### Combining Patterns

You can combine patterns for comprehensive coverage:

1. **HMAW + Adversarial:** Use HMAW for generation, adversarial critics for validation
2. **Ensemble + HMAW:** Run multiple HMAW hierarchies with different models
3. **All Three:** HMAW hierarchy → Ensemble voting → Adversarial validation

### Grit Mode Workflow

The Pivot Engine implements the "Grit Loop" for persistent exploration:

1. **Map** - Understand value flows and trust boundaries
2. **Hypothesize** - Generate concrete attack hypothesis
3. **Prove** - Build smallest PoC
4. **Pivot** - If failed, extract why and try new angle
5. **Repeat** - Until exploit found or hypothesis space exhausted

**Pivot Triggers:**
- 3+ tools without high-confidence findings
- Multiple disproven hypotheses
- Circular reasoning detected
- Need for fresh perspective

**Pivot Strategies:**
- Invert assumption (attack what was assumed safe)
- Zoom in (deep dive on one function)
- Switch modality (static → fuzz → symbolic → on-chain)
- Explore edges (contract boundaries, callbacks)

## Example Workflows

### Basic Adversarial Audit

```python
from cai.agents import get_agent_by_name
from cai.agents.patterns import adversarial_pattern

# Create pattern
pattern = adversarial_pattern(
    name="basic_audit",
    auditors=[
        get_agent_by_name("web3_bug_bounty"),
        get_agent_by_name("static_analyzer"),
    ],
    critics=[
        get_agent_by_name("skeptic_alpha"),
        get_agent_by_name("skeptic_beta"),
        get_agent_by_name("skeptic_gamma"),
    ]
)

# Run audit
results = await pattern.execute("contracts/Vault.sol")

# Review validated findings
for finding in results["validated"]:
    print(f"Finding: {finding['description']}")
    print(f"Critic Score: {finding['scores']['combined']}/10")
```

### HMAW with Grit Mode

```python
from cai.agents.patterns import hmaw_pattern
from cai.agents.pivot_engine import pivot_engine_init, pivot_engine_add_hypothesis

# Initialize pivot engine
pivot_engine_init(stuck_threshold=3)

# Create HMAW pattern
pattern = hmaw_pattern(
    name="thorough_audit",
    ceo=orchestrator,
    managers={"vuln": manager_vuln, "econ": manager_economic},
    workers={
        "vuln": [static_analyzer, fuzzer],
        "econ": [mev_analyzer, flash_loan_analyzer]
    }
)

# Add initial hypotheses
pivot_engine_add_hypothesis(
    hypothesis="First depositor can inflate shares",
    evidence_for="No virtual offset in convertToShares",
    evidence_against="Unknown if minimum deposit exists"
)

# Run audit
results = await pattern.execute("contracts/ERC4626Vault.sol")

# Check if stuck and get pivot suggestion
import json
stuck_status = json.loads(pivot_engine_check_stuck())
if stuck_status["is_stuck"]:
    print(f"Pivot suggestion: {stuck_status['pivot_suggestion']['strategy']}")
```

### Ensemble Consensus Audit

```python
from cai.agents.patterns import ensemble_pattern, VotingMethod

pattern = ensemble_pattern(
    name="consensus_audit",
    agents=[
        get_agent_by_name("web3_bug_bounty"),
        get_agent_by_name("static_analyzer"),
        get_agent_by_name("fuzzing_specialist"),
    ],
    voting=VotingMethod.WEIGHTED_MAJORITY,
    min_agreement=0.3,
    top_k=5
)

results = await pattern.execute("contracts/Protocol.sol")

# Review findings with consensus scores
for finding in results["findings"]:
    print(f"{finding['function_name']}: {finding['vulnerability_type']}")
    print(f"  Votes: {finding['total_votes']}/{results['stats']['total_agents']}")
    print(f"  Agreement: {finding['agreement_ratio']:.0%}")
    print(f"  Voters: {', '.join(finding['voters'])}")
```

## Tool Integration

### IRIS Neuro-Symbolic Workflow

```python
from cai.tools.web3_security import (
    iris_infer_taint_specs,
    iris_enhanced_slither_analysis,
    iris_batch_contextual_filter,
    slither_analyze
)

# Phase 1: Infer taint specifications
with open("contracts/Vault.sol") as f:
    contract_code = f.read()

specs_prompt = iris_infer_taint_specs(
    contract_code=contract_code,
    contract_name="Vault",
    focus_on="all"
)
# Feed to LLM, get back JSON specs

# Phase 2: Run Slither with inferred specs
analysis_instructions = iris_enhanced_slither_analysis(
    target="contracts/Vault.sol",
    inferred_specs=json.dumps(specs)
)

# Run Slither based on instructions
slither_results = slither_analyze("contracts/Vault.sol")

# Phase 3: Contextual filtering
filter_prompt = iris_batch_contextual_filter(
    findings_json=json.dumps(slither_results),
    contract_code=contract_code
)
# Feed to LLM, get back true/false positive classifications
```

## Performance Tuning

### Skeptic Aggressiveness

```bash
# Low: Lenient critics, higher recall
CAI_SKEPTIC_LEVEL="low"

# Medium: Balanced precision/recall (recommended)
CAI_SKEPTIC_LEVEL="medium"

# High: Strict critics, higher precision
CAI_SKEPTIC_LEVEL="high"
```

### Ensemble Voting Strategy

```bash
# Maximum precision (all agents must agree)
CAI_ENSEMBLE_VOTING="unanimous"

# Balanced (weighted by agent performance)
CAI_ENSEMBLE_VOTING="weighted"

# Simple count (one agent, one vote)
CAI_ENSEMBLE_VOTING="simple"

# Learned tie-breaking
CAI_ENSEMBLE_VOTING="permutation"
```

### Grit Mode Sensitivity

```bash
# More persistent (pivots less frequently)
CAI_STUCK_THRESHOLD="5"

# Balanced (default)
CAI_STUCK_THRESHOLD="3"

# More aggressive (pivots quickly)
CAI_STUCK_THRESHOLD="2"
```

## Troubleshooting

### Pattern Not Working

1. Check environment variable: `echo $CAI_PATTERN`
2. Verify agents are registered: Check `cai.agents.__init__.py`
3. Validate pattern config: `pattern.validate()`

### Pivot Engine Not Persisting

1. Check state file: `cat ~/.cai/pivot_engine_state.json`
2. Verify directory permissions: `ls -la ~/.cai/`
3. Re-initialize: `pivot_engine_init()`

### IRIS Tools Not Found

1. Check imports: `from cai.tools.web3_security import iris_infer_taint_specs`
2. Verify file exists: `ls src/cai/tools/web3_security/enhancements/iris.py`
3. Check __init__.py exports

## Further Reading

- [HMAW Research Paper](research-docs/45_Towards_Hierarchical_Multi_.pdf)
- [GPTLens Paper](research-docs/llm-smart-contract-vuln-detect.pdf)
- [IRIS Paper](research-docs/iris-llm.pdf)
- [LLMBugScanner Paper](research-docs/TSE25_LLM-SmartAudit.pdf)
- [Grit Mode Playbook](../.cursor/rules/GRIT.mdc)
