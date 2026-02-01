# Aegis → CAI Migration Guide

## Overview

This guide helps users migrate from standalone Aegis to the integrated CAI+Aegis system, or helps CAI users understand the new Aegis-integrated features.

## For Aegis Users

### What Changed

| Aegis | CAI+Aegis | Notes |
|-------|-----------|-------|
| `aegis` command | `cai` command | Use CAI CLI |
| `~/.aegis/` state | `~/.cai/` state | State file location |
| `AEGIS_*` env vars | `CAI_*` env vars | Environment prefix |
| `from aegis.` | `from cai.` | Import paths |
| `.aegis/mcp.json` | Standard CAI config | MCP configuration |

### Migration Steps

1. **Copy State Files (if you have any):**
   ```bash
   cp -r ~/.aegis/pivot_engine_state.json ~/.cai/ 2>/dev/null || true
   ```

2. **Update Environment Variables:**
   ```bash
   # Old .env
   AEGIS_PATTERN="adversarial"
   AEGIS_SKEPTIC_LEVEL="high"
   
   # New .env
   CAI_PATTERN="adversarial"
   CAI_SKEPTIC_LEVEL="high"
   ```

3. **Update Import Paths (if you have custom code):**
   ```python
   # Old
   from aegis.agents.patterns import adversarial_pattern
   from aegis.agents import skeptic_alpha
   
   # New
   from cai.agents.patterns import adversarial_pattern
   from cai.agents import skeptic_alpha
   ```

4. **Update Command:**
   ```bash
   # Old
   aegis audit contracts/Vault.sol
   
   # New
   cai --agent web3_bug_bounty
   ```

### What Works Exactly The Same

- ✓ All patterns (HMAW, Adversarial, Ensemble)
- ✓ All agents (skeptics, managers, critics)
- ✓ All tools (IRIS, pivot engine, etc.)
- ✓ All configuration options
- ✓ State persistence
- ✓ Hypothesis tracking

### What's Better in CAI+Aegis

1. **Broader Tool Ecosystem** - Access to all CAI tools + Aegis tools
2. **More Agent Types** - Red team, blue team, DFIR, reverse engineering, etc.
3. **Better Integration** - Unified CLI, configuration, and workflow
4. **Active Development** - CAI is actively maintained
5. **Extended Patterns** - CAI's swarm, parallel, sequential patterns + Aegis patterns

## For CAI Users

### What's New

You now have access to Aegis's specialized Web3 security capabilities:

#### 1. New Multi-Agent Patterns

**HMAW (Hierarchical):**
```python
from cai.agents.patterns import hmaw_pattern

pattern = hmaw_pattern(
    name="audit",
    ceo=orchestrator,
    managers={"vuln": manager_vuln, "econ": manager_economic},
    workers={"vuln": [analyzer1, analyzer2]}
)
```

**Adversarial (Auditor vs Critic):**
```python
from cai.agents.patterns import adversarial_pattern

pattern = adversarial_pattern(
    name="audit",
    auditors=[auditor1, auditor2],
    critics=[skeptic_alpha, skeptic_beta, skeptic_gamma]
)
```

**Ensemble (Consensus Voting):**
```python
from cai.agents.patterns import ensemble_pattern, VotingMethod

pattern = ensemble_pattern(
    name="audit",
    agents=[agent1, agent2, agent3],
    voting=VotingMethod.WEIGHTED_MAJORITY
)
```

#### 2. New Agents

**Skeptics (Adversarial Validators):**
- `skeptic_alpha` - Logical analysis
- `skeptic_beta` - Economic analysis
- `skeptic_gamma` - Defense analysis

**Managers (HMAW Coordinators):**
- `manager_vuln` - Vulnerability domain
- `manager_economic` - Economic domain
- `manager_access` - Access control domain

**Specialists:**
- `critic` - GPTLens critic
- `planner` - Pre-Act planner
- `exploit_synthesizer` - Exploit generation
- `poc_generator` - PoC generation

#### 3. New Tools

**IRIS (Neuro-Symbolic):**
- 103.7% improvement in vulnerability detection
- LLM + static analysis combination
- Contextual false positive filtering

**Pivot Engine (Grit Mode):**
- Hypothesis tracking
- Automatic pivot suggestions
- Exhaustion proofs

**Protocol Analyzers:**
- ERC4626 vault security
- Diamond pattern analysis

**Enhancement Tools:**
- Attack economics
- Precision analysis
- Timing analysis
- Invariant generation
- DeFi analyzer
- Enhanced validation

### How to Adopt

**Level 1 - No Changes (Compatible):**
- Keep using CAI exactly as before
- All existing functionality works unchanged

**Level 2 - Add Grit Mode (Easy):**
```bash
export CAI_GRIT_MODE="true"
# Now tracks hypotheses and suggests pivots
```

**Level 3 - Use Adversarial Pattern (Recommended):**
```bash
export CAI_PATTERN="adversarial"
export CAI_SKEPTIC_LEVEL="medium"
# Now uses auditor-critic separation
```

**Level 4 - Full Aegis Integration (Advanced):**
```bash
export CAI_PATTERN="hmaw"
export CAI_SKEPTIC_LEVEL="high"
export CAI_GRIT_MODE="true"
# Now uses full HMAW hierarchy with Grit Mode
```

## Configuration Guide

### Pattern Selection

```bash
# Default: Swarm (existing CAI behavior)
export CAI_PATTERN="swarm"

# HMAW: For complex multi-contract protocols
export CAI_PATTERN="hmaw"

# Adversarial: For high-stakes audits (mainnet, high TVL)
export CAI_PATTERN="adversarial"

# Ensemble: For high-confidence requirements
export CAI_PATTERN="ensemble"
```

### Skeptic Configuration

```bash
# Low: Lenient critics (higher recall)
export CAI_SKEPTIC_LEVEL="low"

# Medium: Balanced (recommended)
export CAI_SKEPTIC_LEVEL="medium"

# High: Strict critics (higher precision)
export CAI_SKEPTIC_LEVEL="high"
```

### Ensemble Voting

```bash
# Weighted: Agent performance influences votes (recommended)
export CAI_ENSEMBLE_VOTING="weighted"

# Permutation: Learned priority for tie-breaking
export CAI_ENSEMBLE_VOTING="permutation"

# Unanimous: All agents must agree (highest precision)
export CAI_ENSEMBLE_VOTING="unanimous"

# Simple: One agent, one vote
export CAI_ENSEMBLE_VOTING="simple"
```

### Grit Mode

```bash
# Enable hypothesis tracking
export CAI_GRIT_MODE="true"

# More sensitive (pivots after 2 tools without findings)
export CAI_STUCK_THRESHOLD="2"

# Default sensitivity
export CAI_STUCK_THRESHOLD="3"

# Less sensitive (more persistent)
export CAI_STUCK_THRESHOLD="5"

# Maximum hypotheses to track
export CAI_MAX_HYPOTHESES="10"
```

## Code Migration Examples

### Old Aegis Code → New CAI Code

**Importing Patterns:**
```python
# Old
from aegis.patterns import adversarial_pattern
from aegis.agents import skeptic_alpha

# New
from cai.agents.patterns import adversarial_pattern
from cai.agents import skeptic_alpha
```

**Using Pivot Engine:**
```python
# Old
from aegis.agents.pivot_engine import pivot_engine_init
pivot_engine_init()

# New (exactly the same!)
from cai.agents.pivot_engine import pivot_engine_init
pivot_engine_init()
```

**Using IRIS:**
```python
# Old
from aegis.tools.web3_security import iris_infer_taint_specs

# New
from cai.tools.web3_security import iris_infer_taint_specs
```

## Testing Migration

### 1. Verify Installation
```bash
cd /home/dok/tools/cai
python3 verify_aegis_integration.py
```

Expected output:
```
✅ INTEGRATION SUCCESSFUL - All components verified!
Files Found: 33/33
Import Errors: 0
```

### 2. Test Pattern Import
```python
from cai.agents.patterns import (
    hmaw_pattern,
    adversarial_pattern,
    ensemble_pattern
)
print("✓ Patterns imported")
```

### 3. Test Agent Import
```python
from cai.agents import (
    skeptic_alpha,
    skeptic_beta,
    skeptic_gamma,
    manager_vuln
)
print("✓ Agents imported")
```

### 4. Test Tools Import
```python
from cai.tools.web3_security import (
    iris_infer_taint_specs,
    iris_contextual_filter
)
from cai.agents.pivot_engine import (
    pivot_engine_init,
    pivot_engine_add_hypothesis
)
print("✓ Tools imported")
```

## Feature Comparison

| Feature | Standalone Aegis | CAI+Aegis | Winner |
|---------|-----------------|-----------|--------|
| Web3 Patterns | ✓ | ✓ | Tie |
| Skeptic Agents | ✓ | ✓ | Tie |
| HMAW Pattern | ✓ | ✓ | Tie |
| IRIS Integration | ✓ | ✓ | Tie |
| Grit Mode | ✓ | ✓ | Tie |
| General Security | ✗ | ✓ | CAI+Aegis |
| Red Team Tools | ✗ | ✓ | CAI+Aegis |
| DFIR Capabilities | ✗ | ✓ | CAI+Aegis |
| Web Pentesting | ✗ | ✓ | CAI+Aegis |
| Broader Ecosystem | ✗ | ✓ | CAI+Aegis |
| Active Development | ? | ✓ | CAI+Aegis |

**Recommendation:** Use CAI+Aegis for all new projects. It has everything Aegis has, plus more.

## Rollback Plan

If you need to rollback (unlikely):

1. **Environment variables** - Just unset new variables
2. **Code** - New files don't affect existing functionality
3. **State** - Delete `~/.cai/pivot_engine_state.json`
4. **Pattern** - Set `CAI_PATTERN="swarm"` (default)

Nothing breaks existing CAI functionality. Integration is purely additive.

## Support & Resources

1. **Documentation:** `docs/aegis-integration.md`
2. **Quick Start:** `AEGIS_QUICK_START.md`
3. **Summary:** `AEGIS_INTEGRATION_SUMMARY.md`
4. **Research Papers:** `research-docs/` directory
5. **Original Aegis:** `/home/dok/tools/aegis/` (for reference)

## FAQ

**Q: Do I need to use Aegis features?**  
A: No, they're opt-in. Default behavior is unchanged.

**Q: Can I mix Aegis and CAI patterns?**  
A: Yes! Use `CAI_PATTERN` to choose, or programmatically create custom patterns.

**Q: Are Aegis features slower?**  
A: Adversarial is slower (2-phase), HMAW is similar speed (parallel), Ensemble is similar.

**Q: What's the recommended pattern?**  
A: Adversarial for high-stakes, HMAW for complex, Ensemble for high-confidence, Swarm for general.

**Q: Does this work with existing CAI agents?**  
A: Yes! You can use Aegis patterns with any CAI agents.

**Q: How do I know if integration worked?**  
A: Run `python3 verify_aegis_integration.py` - should show all green checkmarks.

---

**Migration Date:** January 31, 2026  
**Status:** ✅ Complete - All Aegis capabilities available in CAI
