# Aegis Integration - Quick Start Guide

## 🎯 What You Got

CAI now includes **Aegis's research-backed Web3 security patterns** that achieved:
- **30.7%** improvement (HMAW)
- **77%** improvement (Adversarial)
- **103.7%** improvement (IRIS)
- **60%** top-5 detection (Ensemble)

## 🚀 Quick Usage

### 1. Use Adversarial Pattern (Recommended for High-Stakes Audits)

```bash
# Set environment
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="high"

# Run audit - auditors generate findings, skeptics validate them
cai --agent web3_bug_bounty
```

**What happens:**
1. Multiple auditors generate vulnerability candidates (high recall)
2. Skeptics evaluate each finding on logic, economics, and defenses
3. Only findings that survive all skeptics are reported (high precision)

### 2. Use HMAW Pattern (Best for Complex Protocols)

```bash
# Set environment
export CAI_PATTERN="hmaw"

# Run audit - CEO → Managers → Workers hierarchy
cai --agent web3_bug_bounty
```

**What happens:**
1. CEO sets high-level audit objectives
2. Domain managers (Vuln, Economic, Access) create focused tasks
3. Specialist workers execute tasks in parallel
4. Results aggregated back up the hierarchy

### 3. Use Ensemble Pattern (Best for High Confidence)

```bash
# Set environment
export CAI_PATTERN="ensemble"
export CAI_ENSEMBLE_VOTING="weighted"

# Run audit - multiple agents vote on findings
cai --agent web3_bug_bounty
```

**What happens:**
1. Multiple agents analyze the same target
2. Findings are aggregated using consensus voting
3. Only findings with sufficient agreement are reported
4. Agent performance weights influence voting

### 4. Enable Grit Mode (Persistent Hypothesis Tracking)

```bash
# Set environment
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="3"

# Run audit - automatically pivots when stuck
cai --agent web3_bug_bounty
```

**What happens:**
1. Attack hypotheses are tracked with status
2. When stuck (3 tools without findings), auto-suggests pivots
3. Pivots: Invert assumptions, zoom in, switch modality, explore edges
4. Generates exhaustion proof if no exploits found

### 5. Use IRIS for Enhanced Static Analysis

```python
from cai.tools.web3_security import (
    iris_infer_taint_specs,
    iris_enhanced_slither_analysis,
    iris_contextual_filter
)

# Phase 1: LLM infers taint specs
specs = iris_infer_taint_specs(contract_code, "MyVault")

# Phase 2: Run Slither with specs
analysis = iris_enhanced_slither_analysis("contracts/Vault.sol", specs)

# Phase 3: LLM filters false positives
verdict = iris_contextual_filter(finding, source_code, sink_code)
```

**What happens:**
1. LLM identifies taint sources, sinks, and propagators
2. Static analysis runs with LLM-guided focus
3. LLM contextually filters results
4. Result: 103.7% more true positives, 5% fewer false positives

## 🎓 New Agents Available

Run `cai --list-agents` to see all agents. New Aegis agents:

| Agent | Purpose |
|-------|---------|
| `skeptic_alpha` | Logical denial - breaks assumptions |
| `skeptic_beta` | Economic analysis - proves unprofitability |
| `skeptic_gamma` | Defense analysis - finds protections |
| `manager_vuln` | HMAW vulnerability coordinator |
| `manager_economic` | HMAW economic coordinator |
| `manager_access` | HMAW access control coordinator |
| `critic` | GPTLens-style critic |
| `planner` | Pre-Act planning |
| `exploit_synthesizer` | Exploit generation |
| `poc_generator` | PoC generation |
| `attributor` | Error attribution |

## 🛠️ New Tools Available

### Pivot Engine (Grit Mode)
```python
from cai.agents.pivot_engine import *

pivot_engine_init()  # Initialize tracking
pivot_engine_add_hypothesis("First depositor attack possible")
pivot_engine_check_stuck()  # Check if should pivot
pivot_engine_exhaustion_proof()  # Generate completion proof
```

### IRIS Tools
```python
from cai.tools.web3_security import *

iris_infer_taint_specs(code, name)  # Infer taint specs
iris_enhanced_slither_analysis(path, specs)  # Enhanced Slither
iris_contextual_filter(finding, src, sink)  # Filter FPs
```

### Protocol Analyzers
```python
# ERC4626 vault analysis
from cai.tools.web3_security.protocols import *

# Diamond pattern analysis
# (Import and use as needed)
```

## 📊 Pattern Comparison

| Feature | Swarm (Default) | HMAW | Adversarial | Ensemble |
|---------|----------------|------|-------------|----------|
| **Best For** | General use | Complex protocols | High precision | High confidence |
| **Speed** | Fast | Medium | Slower | Medium |
| **Precision** | Medium | High | Very High | High |
| **Recall** | High | High | Medium | Medium |
| **False Positives** | Medium | Low | Very Low | Low |
| **Setup** | None | Configure hierarchy | Configure auditors/critics | Configure agents |

## 🎮 Configuration Presets

### Maximum Precision (Minimize False Positives)
```bash
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="high"
export CAI_ENSEMBLE_VOTING="unanimous"
export CAI_GRIT_MODE="true"
```

### Maximum Coverage (Find Everything)
```bash
export CAI_PATTERN="hmaw"
export CAI_SKEPTIC_LEVEL="low"
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="5"
```

### Balanced (Recommended)
```bash
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="medium"
export CAI_ENSEMBLE_VOTING="weighted"
export CAI_GRIT_MODE="true"
export CAI_STUCK_THRESHOLD="3"
```

### Fast Triage
```bash
export CAI_PATTERN="ensemble"
export CAI_ENSEMBLE_VOTING="simple"
export CAI_MIN_AGREEMENT="0.5"
export CAI_TOP_K="3"
```

## 🔥 Grit Mode Explained

The Pivot Engine implements relentless bug hunting:

**The Grit Loop:**
1. Map value flows and trust boundaries
2. Write concrete exploit hypothesis
3. Build smallest proof (mental model, then PoC)
4. If fails, extract why; update model
5. Pivot: new angle, new tool, or new contract seam
6. Repeat until exploit found or space exhausted

**Pivot Strategies:**
- **Invert Assumption** - Attack what was assumed safe
- **Zoom In** - Deep dive on one function
- **Switch Modality** - Static → Fuzz → Symbolic → On-chain
- **Explore Edges** - Contract boundaries, callbacks

**Never declares "no bugs" without exhaustion proof.**

## 📚 Learning Path

### Beginner
1. Start with default swarm pattern
2. Try Grit Mode (`CAI_GRIT_MODE="true"`)
3. Experiment with IRIS tools

### Intermediate
1. Use Adversarial pattern for critical audits
2. Understand skeptic agent roles
3. Tune voting thresholds

### Advanced
1. Create custom HMAW hierarchies
2. Combine multiple patterns
3. Build custom ensemble configurations
4. Write protocol-specific analyzers

## 🐛 Troubleshooting

### "Agent not found"
```bash
# List available agents
cai --list-agents | grep -E "(skeptic|manager)"

# Verify registration
python3 -c "from cai.agents import AVAILABLE_AGENTS; print(AVAILABLE_AGENTS)"
```

### "Pattern not working"
```bash
# Check environment
echo $CAI_PATTERN

# Verify pattern exists
python3 -c "from cai.agents.patterns import PATTERNS; print(list(PATTERNS.keys()))"
```

### "Import errors"
```bash
# Run verification
python3 verify_aegis_integration.py
```

## 📖 Full Documentation

- **Complete Guide:** `docs/aegis-integration.md`
- **Integration Summary:** `AEGIS_INTEGRATION_SUMMARY.md`
- **Research Papers:** `research-docs/` directory

## 🎯 Example Workflows

### Basic Adversarial Audit
```python
from cai.agents.patterns import adversarial_pattern
from cai.agents import get_agent_by_name

pattern = adversarial_pattern(
    name="my_audit",
    auditors=[
        get_agent_by_name("web3_bug_bounty"),
    ],
    critics=[
        get_agent_by_name("skeptic_alpha"),
        get_agent_by_name("skeptic_beta"),
        get_agent_by_name("skeptic_gamma"),
    ]
)

# Run and review validated findings only
results = await pattern.execute("target.sol")
print(f"Validated: {len(results['validated'])}")
print(f"Rejected: {len(results['rejected'])}")
```

### HMAW with Grit Mode
```python
from cai.agents.patterns import hmaw_pattern
from cai.agents.pivot_engine import pivot_engine_init, pivot_engine_add_hypothesis

# Initialize Grit Mode
pivot_engine_init(stuck_threshold=3)

# Add hypothesis
pivot_engine_add_hypothesis(
    "First depositor can inflate shares",
    evidence_for="No virtual offset",
    evidence_against="Might have min deposit"
)

# Create HMAW pattern
pattern = hmaw_pattern(
    name="thorough_audit",
    ceo=get_agent_by_name("web3_bug_bounty"),
    managers={
        "vuln": get_agent_by_name("manager_vuln"),
        "econ": get_agent_by_name("manager_economic"),
    }
)

# Audit runs, automatically pivots if stuck
results = await pattern.execute("target.sol")
```

## ⚡ Performance Tips

1. **Start with Adversarial** - Best balance of precision and coverage
2. **Use High Skeptic Level** - For critical/mainnet contracts
3. **Enable Grit Mode** - Ensures thorough exploration
4. **Tune Stuck Threshold** - Lower (2) = more pivots, Higher (5) = more persistent
5. **Use IRIS** - Significantly reduces false positives

## 🏆 Success Metrics

Track your audit quality:
- **Grit Score** - Measures persistence (higher = more thorough)
- **Hypotheses Tested** - Attack vectors explored
- **Pivot Count** - Angle changes (shows adaptability)
- **Coverage Estimate** - % of attack surface examined
- **Critic Scores** - Finding quality (0-10 scale)
- **Agent Performance** - Historical accuracy tracking

## 🔄 Upgrade Path

All existing CAI functionality works unchanged. New features are opt-in:

**To upgrade gradually:**
1. Start using Grit Mode with existing workflow
2. Add skeptics for finding validation
3. Try Adversarial pattern for important audits
4. Explore HMAW for complex protocols
5. Use Ensemble for critical findings

**No breaking changes** - defaults maintain backward compatibility.

---

**Need Help?** Check `docs/aegis-integration.md` for detailed examples and API reference.
