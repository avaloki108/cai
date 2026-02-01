# Aegis Features Now Available in CAI

## 🎨 Multi-Agent Patterns (3 New)

### 1. HMAW (Hierarchical Multi-Agent Workflow)
**Research:** 30.7% improvement over baseline

```python
from cai.agents.patterns import hmaw_pattern

pattern = hmaw_pattern(
    name="web3_audit",
    ceo=orchestrator_agent,
    managers={
        "vulnerability": manager_vuln,
        "economic": manager_economic,
        "access": manager_access
    },
    workers={
        "vulnerability": [static_analyzer, fuzzer],
        "economic": [mev_analyzer, flash_loan_analyzer],
        "access": [permission_checker]
    }
)
```

**Key Features:**
- CEO-Manager-Worker hierarchy
- Skip connections preserve context
- Parallel execution at all levels
- Domain-specific expertise

### 2. Adversarial Pattern (GPTLens)
**Research:** 33.3% → 59.0% accuracy (+77%)

```python
from cai.agents.patterns import adversarial_pattern

pattern = adversarial_pattern(
    name="web3_audit",
    auditors=[auditor1, auditor2, auditor3],
    critics=[skeptic_alpha, skeptic_beta, skeptic_gamma],
    auditor_temperature=0.8,
    min_critic_score=5.0
)
```

**Key Features:**
- Auditors generate diverse candidates (high recall)
- Critics evaluate on logic, economics, defenses (high precision)
- Consensus voting for validation
- Dramatically reduces false positives

### 3. Ensemble Pattern (LLMBugScanner)
**Research:** 60% top-5 detection accuracy

```python
from cai.agents.patterns import ensemble_pattern, VotingMethod

pattern = ensemble_pattern(
    name="web3_audit",
    agents=[agent1, agent2, agent3],
    voting=VotingMethod.WEIGHTED_MAJORITY,
    min_agreement=0.3
)
```

**Key Features:**
- Multi-model consensus
- 4 voting methods (weighted, permutation, unanimous, simple)
- Performance-based weighting
- Specialist boost for domain experts

## 🤖 Specialized Agents (12 New)

### Skeptic Agents (Adversarial Review)

#### Skeptic Alpha - The Logical Denier
```python
from cai.agents import skeptic_alpha

# Tools:
# - challenge_assumptions
# - find_logical_flaws
# - verify_causal_chain
# - identify_contradictions
# - render_logical_verdict
```

**Purpose:** Obliterates findings through logical analysis. Breaks assumptions, finds contradictions, severs causal chains.

#### Skeptic Beta - The Economic Executioner
```python
from cai.agents import skeptic_beta

# Tools:
# - calculate_attack_cost
# - estimate_attack_profit
# - analyze_roi
# - check_mev_opportunity
# - render_economic_verdict
```

**Purpose:** Destroys findings by proving economic impossibility. Calculates costs, profits, ROI, MEV competition.

#### Skeptic Gamma - The Defense Analyst
```python
from cai.agents import skeptic_gamma

# Tools:
# - find_access_controls
# - find_input_validation
# - find_reentrancy_guards
# - find_rate_limiting
# - find_emergency_stops
# - render_defense_verdict
```

**Purpose:** Exposes protective mechanisms that block attacks. Finds guards, validations, limits.

### HMAW Manager Agents

#### Vulnerability Manager
```python
from cai.agents import manager_vuln

# Tools:
# - prioritize_vulnerability_vectors
# - generate_vulnerability_hypotheses
# - coordinate_worker_findings
```

**Purpose:** Coordinates vulnerability hunting. Translates CEO goals into specific attack vectors.

#### Economic Manager
```python
from cai.agents import manager_economic

# Tools:
# - prioritize_economic_vectors
# - generate_economic_hypotheses
# - coordinate_economic_findings
```

**Purpose:** Coordinates economic attack analysis. Generates ROI calculations for attack scenarios.

#### Access Control Manager
```python
from cai.agents import manager_access

# Tools:
# - prioritize_access_vectors
# - generate_access_hypotheses
# - coordinate_access_findings
```

**Purpose:** Coordinates permission analysis. Builds access control matrix, maps escalation paths.

### Additional Specialists

- **`critic`** - GPTLens-style critic for finding evaluation
- **`planner`** - Pre-Act planning for multi-step audits
- **`exploit_synthesizer`** - Generates exploit code
- **`poc_generator`** - Generates proof-of-concept tests
- **`attributor`** - Error attribution and root cause analysis

## 🛠️ New Tools (30+)

### Pivot Engine (Grit Mode)
```python
from cai.agents.pivot_engine import (
    pivot_engine_init,              # Initialize tracking
    pivot_engine_add_hypothesis,    # Add hypothesis
    pivot_engine_record_attempt,    # Record test
    pivot_engine_check_stuck,       # Check if stuck
    pivot_engine_exhaustion_proof,  # Generate proof
    pivot_engine_switch_modality    # Change approach
)
```

**Capabilities:**
- Tracks attack hypotheses (pending/confirmed/disproven)
- Detects when stuck (no findings after N tools)
- Suggests pivots: invert, zoom in, switch modality, explore edges
- Generates exhaustion proof when complete
- Persists state to `~/.cai/pivot_engine_state.json`

### IRIS (Neuro-Symbolic Integration)
```python
from cai.tools.web3_security import (
    iris_infer_taint_specs,         # Phase 1: LLM infers specs
    iris_enhanced_slither_analysis,  # Phase 2: Enhanced Slither
    iris_contextual_filter,          # Phase 3: Filter FPs
    iris_generate_custom_detector,   # Generate custom detectors
    iris_batch_contextual_filter     # Batch filtering
)
```

**Capabilities:**
- LLM identifies taint sources, sinks, propagators
- Static analysis runs with LLM-guided specifications
- LLM contextually filters false positives
- 103.7% improvement in true positive detection
- 5% reduction in false discovery rate

### Protocol Analyzers

#### ERC4626 Analyzer
```python
from cai.tools.web3_security.protocols.erc4626_analyzer import *
```

**Detects:**
- First depositor attacks
- Inflation attacks
- Share price manipulation
- Donation attacks
- Vault reentrancy

#### Diamond Analyzer
```python
from cai.tools.web3_security.protocols.diamond_analyzer import *
```

**Detects:**
- Facet collisions
- Storage collisions
- Selector conflicts
- Upgrade path vulnerabilities

### Enhancement Tools

#### Attack Economics
```python
from cai.tools.web3_security.enhancements.attack_economics import *
```
- Attack cost calculation
- Profit estimation
- ROI analysis
- MEV competition assessment

#### Precision Analysis
```python
from cai.tools.web3_security.enhancements.precision import *
```
- Rounding error detection
- Division precision loss
- Share manipulation vectors

#### Timing Analysis
```python
from cai.tools.web3_security.enhancements.timing import *
```
- Race condition detection
- Block timestamp dependencies
- Transaction ordering issues

#### Invariant Generation
```python
from cai.tools.web3_security.enhancements.invariant_gen import *
```
- Automated invariant generation
- State invariants
- Economic invariants
- Relationship invariants

#### DeFi Analyzer
```python
from cai.tools.web3_security.enhancements.defi_analyzer import *
```
- AMM analysis (Uniswap, Curve, Balancer)
- Lending protocol analysis (Aave, Compound)
- Yield vault analysis

#### Enhanced Validation
```python
from cai.tools.web3_security.enhancements.validation import *
```
- Multi-layer validation
- Pattern-based filtering
- Confidence scoring

### Additional Core Tools

- **`council.py`** - Finding review council for validation
- **`triage.py`** - Intelligent finding prioritization
- **`slither_mcp_client.py`** - Modern MCP-based Slither integration
- **`foundry.py`** - Foundry testing integration
- **`fork_test.py`** - On-chain fork testing utilities
- **`audit_autonomous.py`** - Autonomous audit coordinator

## 🎮 Usage Patterns

### Pattern 1: Maximum Precision
```bash
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="high"
cai --agent web3_bug_bounty
```
**Use for:** Mainnet audits, high TVL protocols, critical contracts

### Pattern 2: Maximum Coverage
```bash
export CAI_PATTERN="hmaw"
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="5"
cai --agent web3_bug_bounty
```
**Use for:** Complex protocols, multi-contract systems, comprehensive reviews

### Pattern 3: Maximum Confidence
```bash
export CAI_PATTERN="ensemble"
export CAI_ENSEMBLE_VOTING="unanimous"
cai --agent web3_bug_bounty
```
**Use for:** Critical findings, when you need multiple agents to agree

### Pattern 4: Persistent Hunting
```bash
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="3"
cai --agent web3_bug_bounty
```
**Use for:** Bug bounties, when you must find something, relentless exploration

## 📊 Feature Matrix

| Feature | Available | Config Var | Default |
|---------|-----------|------------|---------|
| HMAW Pattern | ✅ | `CAI_PATTERN=hmaw` | No |
| Adversarial Pattern | ✅ | `CAI_PATTERN=adversarial` | No |
| Ensemble Pattern | ✅ | `CAI_PATTERN=ensemble` | No |
| Skeptic Agents | ✅ | `CAI_SKEPTIC_LEVEL` | medium |
| Manager Agents | ✅ | Used in HMAW | - |
| Pivot Engine | ✅ | `CAI_GRIT_MODE=true` | false |
| IRIS Tools | ✅ | Always available | - |
| Protocol Analyzers | ✅ | Always available | - |
| Autonomous Audit | ✅ | Always available | - |

## 🚀 Performance Expectations

Based on research papers:

| Metric | Baseline | With HMAW | With Adversarial | With IRIS | With Ensemble |
|--------|----------|-----------|------------------|-----------|---------------|
| Detection Rate | 100% | 130.7% | 177% | 203.7% | 160% |
| False Positives | 100% | 70% | 40% | 95% | 60% |
| Top-1 Accuracy | 33.3% | - | 59.0% | - | - |
| Top-5 Accuracy | ~40% | - | - | - | 60% |

## 🎯 Recommended Combinations

### For Bug Bounty Hunting
```bash
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="high"
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="2"
```

### For Professional Audits
```bash
export CAI_PATTERN="hmaw"
export CAI_SKEPTIC_LEVEL="medium"
export CAI_GRIT_MODE="true"
```

### For Quick Triage
```bash
export CAI_PATTERN="ensemble"
export CAI_ENSEMBLE_VOTING="simple"
export CAI_TOP_K="3"
```

### For Research/Deep Analysis
```bash
export CAI_PATTERN="hmaw"
export CAI_SKEPTIC_LEVEL="low"
export CAI_GRIT_MODE="true"
export CAI_MAX_HYPOTHESES="20"
```

## 📖 Documentation Index

1. **Quick Start** - `AEGIS_QUICK_START.md`
2. **Complete Guide** - `docs/aegis-integration.md`
3. **Migration Guide** - `AEGIS_MIGRATION_GUIDE.md`
4. **Integration Summary** - `AEGIS_INTEGRATION_SUMMARY.md`
5. **This File** - Feature reference

## 🔧 Advanced Configuration

### Fine-Tune Adversarial Pattern
```bash
CAI_PATTERN="adversarial"
CAI_AUDITOR_TEMPERATURE="0.9"      # Higher = more diverse findings
CAI_MIN_CRITIC_SCORE="6.0"         # Higher = stricter validation
CAI_CONSENSUS_THRESHOLD="0.7"      # Higher = more critics must agree
```

### Fine-Tune Ensemble Pattern
```bash
CAI_PATTERN="ensemble"
CAI_ENSEMBLE_VOTING="weighted"
CAI_MIN_AGREEMENT="0.4"            # % of agents that must agree
CAI_MIN_CONFIDENCE="0.6"           # Minimum confidence per vote
CAI_TOP_K="10"                     # Number of findings to return
```

### Fine-Tune HMAW Pattern
```bash
CAI_PATTERN="hmaw"
CAI_SKIP_CONNECTIONS="true"        # Enable skip connections
CAI_PARALLEL_MANAGERS="true"       # Run managers in parallel
CAI_PARALLEL_WORKERS="true"        # Run workers in parallel
```

### Fine-Tune Grit Mode
```bash
CAI_GRIT_MODE="true"
CAI_STUCK_THRESHOLD="3"            # Tools before pivoting (2-5)
CAI_MAX_HYPOTHESES="15"            # Max hypotheses to track
```

## 🎓 Learning Resources

### Research Papers (Included)
1. `research-docs/45_Towards_Hierarchical_Multi_.pdf` - HMAW
2. `research-docs/llm-smart-contract-vuln-detect.pdf` - GPTLens
3. `research-docs/iris-llm.pdf` - IRIS
4. `research-docs/TSE25_LLM-SmartAudit.pdf` - LLMBugScanner

### Code Examples
- `examples/` directory (if created)
- `docs/aegis-integration.md` - Comprehensive examples
- `AEGIS_QUICK_START.md` - Quick reference examples

## 🏆 Success Stories from Research

### HMAW Pattern
- **Improvement:** 30.7% over baseline
- **Key Insight:** Skip connections prevent information loss through hierarchy
- **Best For:** Complex multi-domain analysis

### GPTLens (Adversarial)
- **Improvement:** 33.3% → 59.0% top-1 accuracy
- **Key Insight:** Generation harder than discrimination
- **Best For:** High-precision requirements

### IRIS
- **Improvement:** 103.7% in vulnerability detection
- **Key Insight:** LLM guidance improves static analysis
- **Best For:** False positive reduction

### LLMBugScanner (Ensemble)
- **Achievement:** 60% top-5 detection accuracy
- **Key Insight:** Different models excel at different vulnerability types
- **Best For:** High-confidence consensus

## 💎 Unique Capabilities

### 1. Constructive Skepticism
Skeptics don't just reject findings - they suggest alternatives:
- "Try attacking via path X instead"
- "This would work IF condition Y held - check for Y"
- Tracked suggestions ensure follow-up

### 2. Hypothesis State Machine
Pivot engine tracks every hypothesis:
- Status: pending → testing → confirmed/disproven
- Evidence for and against
- Tools used
- Next recommended action

### 3. Exhaustion Proofs
Never declares "no bugs" without proof:
- Documents all hypotheses tested
- Lists all tools run
- Shows all modalities tried
- Calculates coverage estimate
- Provides confidence in safety

### 4. Adaptive Tool Selection
Autonomous coordinator intelligently selects tools:
- Detects protocol characteristics (vault, AMM, lending, etc.)
- Generates hypotheses based on patterns
- Prioritizes tools for detected characteristics
- Adapts strategy based on findings

## 🔥 Power User Tips

### Tip 1: Combine Patterns
```python
# Use HMAW for structure, Adversarial for validation
hmaw_with_critics = hmaw_pattern(
    name="thorough",
    ceo=orchestrator,
    managers={"vuln": manager_vuln},
    workers={"vuln": [auditor1, auditor2]}  # Auditors as workers
)
# Then pass results through adversarial critics
```

### Tip 2: Use Grit Mode Always
```bash
# Always track hypotheses - even if not stuck, it helps
export CAI_GRIT_MODE="true"
```

### Tip 3: Start Strict, Relax If Needed
```bash
# Start with high precision
export CAI_SKEPTIC_LEVEL="high"
# If too many findings rejected, lower to "medium"
```

### Tip 4: Monitor Agent Performance
```python
from cai.agents.patterns.ensemble import AGENT_PERFORMANCE

# Check which agents are most accurate
for agent_name, history in AGENT_PERFORMANCE.items():
    print(f"{agent_name}: {history.accuracy():.1%} accuracy")
```

### Tip 5: Use IRIS for Critical Functions
```python
# For high-value functions, use IRIS contextual filter
verdict = iris_contextual_filter(
    finding_description=finding,
    source_code=get_context(source),
    sink_code=get_context(sink)
)
```

## 🎪 Demo Commands

Try these to see the new features:

```bash
# 1. Basic adversarial audit
export CAI_PATTERN="adversarial"
cai --agent web3_bug_bounty

# 2. HMAW hierarchy audit
export CAI_PATTERN="hmaw"
cai --agent web3_bug_bounty

# 3. Ensemble consensus audit
export CAI_PATTERN="ensemble"
export CAI_ENSEMBLE_VOTING="weighted"
cai --agent web3_bug_bounty

# 4. Grit Mode with auto-pivoting
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="2"
cai --agent web3_bug_bounty
```

---

**All Aegis features are now available in CAI. The progression of capabilities continues uninterrupted.** 🚀
