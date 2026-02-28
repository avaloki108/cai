# Web3 Security Agents Overview

The CAI framework includes a specialized suite of twelve cybersecurity AI agents designed for comprehensive Web3 security auditing. These agents form the **Aegis Ensemble** - a coordinated multi-agent system that combines adversarial review, multi-step planning, and automated exploit synthesis.

## Architecture

All Web3 agents run through the **CAI runtime** (Agent Factory → Runner → Turns/Interactions).
The primary audit paths are:

1. **Deterministic pipeline** (`EliteWeb3Pipeline` in `src/cai/web3/pipeline.py`):
   Discovery → Risk Queue → Skeptic Gate → Fork Exploit → Formal
2. **Judge-gated bounty** (see [Judge Gate pipeline](../../judge_gate_pipeline.md)):
   `web3_bug_bounty_agent` → `defi_bounty_judge_agent` → `retester_agent`

```
                    ┌──────────────────────┐
                    │  CAI Agent Factory   │
                    │  & Runner (Turns)    │
                    └──────────┬───────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │   Planner    │   │   Managers   │   │  Attributor  │
    │  (Pre-Act)   │   │ (Specialized)│   │(Classification)│
    └──────┬───────┘   └──────┬───────┘   └──────────────┘
           │                  │
           │    ┌─────────────┼─────────────┐
           ▼    ▼             ▼             ▼
    ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
    │    Critic     │  │   Skeptics    │  │  Synthesizers │
    │  (GPTLens)    │  │ (Adversarial) │  │    (PoC)      │
    └───────────────┘  └───────────────┘  └───────────────┘
```

## Agent Categories

### 1. Orchestration Layer

| Agent | Purpose | Key Capability |
|-------|---------|----------------|
| **Web3 Orchestrator** | Master coordination | Coordinates all agents through audit phases |
| **Planner** | Multi-step planning | Pre-Act methodology for systematic audits |

### 2. Management Layer

| Agent | Purpose | Key Capability |
|-------|---------|----------------|
| **Manager Vuln** | Vulnerability detection | Pattern-based vulnerability classification |
| **Manager Economic** | Economic analysis | Flash loan, oracle, MEV attack detection |
| **Manager Access** | Access control | Privilege escalation, admin key analysis |

### 3. Adversarial Layer

| Agent | Purpose | Key Capability |
|-------|---------|----------------|
| **Critic** | Finding evaluation | GPTLens-style scoring (correctness, severity, profitability) |
| **Skeptic Alpha** | Logical denial | Attack assumption chains and logical foundations |
| **Skeptic Beta** | Technical denial | Challenge technical implementation claims |
| **Skeptic Gamma** | Economic denial | Challenge economic viability of exploits |

### 4. Synthesis Layer

| Agent | Purpose | Key Capability |
|-------|---------|----------------|
| **Exploit Synthesizer** | Attack construction | Build multi-step exploit paths |
| **PoC Generator** | Test generation | Generate Foundry-based proof-of-concept tests |
| **Attributor** | Classification | Map findings to SWC/DASP/CWE taxonomies |

## Workflow

### Phase 1: Discovery
```
Web3 Orchestrator
    └── Planner: Generate audit plan
        └── detect_web3_repo_context()
        └── Identify architecture, proxies, oracles
```

### Phase 2: Analysis
```
Planner
    └── Manager Vuln: Run static analysis
        └── Slither, Mythril, Securify
    └── Manager Economic: Analyze DeFi vectors
        └── Oracle, flash loan, MEV analysis
    └── Manager Access: Map access controls
        └── Privilege paths, admin keys
```

### Phase 3: Adversarial Review
```
Manager outputs
    └── Critic: Score findings (0-10)
        └── Correctness, Severity, Profitability
    └── Skeptic Alpha: Challenge logic
    └── Skeptic Beta: Challenge technical claims
    └── Skeptic Gamma: Challenge economics
        └── Reject findings with score < 5
```

### Phase 4: Synthesis
```
Validated findings
    └── Exploit Synthesizer: Build attack paths
    └── PoC Generator: Create Foundry tests
    └── Attributor: Classify to SWC/DASP
```

## Configuration

### Basic Usage

```bash
# Run full Aegis audit
cai --agent web3_orchestrator --target ./contracts/

# Run specific phase
cai --agent manager_vuln --target ./contracts/

# Run adversarial review on findings
cai --agent critic --input findings.json
```

### agents.yml Configuration

```yaml
# Parallel analysis phase
parallel_agents:
  - name: manager_vuln
    prompt: "Scan {target} for vulnerability patterns"
  - name: manager_economic
    prompt: "Analyze {target} for economic attack vectors"
  - name: manager_access
    prompt: "Map access controls in {target}"

# Sequential adversarial review
sequential_agents:
  - name: critic
    depends_on: [manager_vuln, manager_economic, manager_access]
  - name: skeptic_alpha
    depends_on: [critic]
  - name: skeptic_beta
    depends_on: [skeptic_alpha]
  - name: skeptic_gamma
    depends_on: [skeptic_beta]
```

## Key Features

### GPTLens-Style Review

Based on the GPTLens paper, the Critic agent evaluates findings on three dimensions:

- **Correctness (0-10)**: Is the reasoning logically sound?
- **Severity (0-10)**: How bad is the actual impact?
- **Profitability (0-10)**: Would an attacker bother?

Findings scoring < 5 on ANY dimension are REJECTED.

### Pre-Act Planning

Based on the Pre-Act research, the Planner agent:

- Generates comprehensive multi-step plans BEFORE execution
- Each step specifies: action, agent, reasoning, expected output
- Plans are refined iteratively as tool outputs come in
- Achieves 70% improvement in Action Recall

### Triple Skeptic Defense

Three specialized skeptics attack findings from different angles:

1. **Alpha**: "Your assumption chain is broken"
2. **Beta**: "The code path is unreachable"
3. **Gamma**: "The attack is unprofitable"

Only findings that survive all three skeptics proceed to synthesis.

## Performance Targets

| Metric | Target |
|--------|--------|
| Precision | >= 80% |
| Recall | >= 70% |
| F1 Score | >= 0.75 |
| False Positive Rate | <= 20% |
| PoC Compilation Rate | 100% |
| PoC Execution Pass Rate | >= 80% |

## Available Agents

### Core Agents

| Agent | Module | Description |
|-------|--------|-------------|
| `planner` | `cai.agents.planner` | Pre-Act multi-step planning |
| `critic` | `cai.agents.critic` | GPTLens-style adversarial review |
| `skeptic_alpha` | `cai.agents.skeptic_alpha` | Logical assumption denial |
| `skeptic_beta` | `cai.agents.skeptic_beta` | Technical implementation denial |
| `skeptic_gamma` | `cai.agents.skeptic_gamma` | Economic viability denial |
| `manager_vuln` | `cai.agents.manager_vuln` | Vulnerability pattern management |
| `manager_economic` | `cai.agents.manager_economic` | Economic attack management |
| `manager_access` | `cai.agents.manager_access` | Access control analysis |
| `exploit_synthesizer` | `cai.agents.exploit_synthesizer` | Attack path construction |
| `poc_generator` | `cai.agents.poc_generator` | Foundry test generation |
| `attributor` | `cai.agents.attributor` | Vulnerability classification |
| `web3_bug_bounty` | `cai.agents.web3_bug_bounty` | Master orchestrator |

### Specialized Agents

| Agent | Module | Description |
|-------|--------|-------------|
| `web3_discovery_agent` | `cai.agents.web3_discovery_agent` | Protocol discovery |
| `web3_gctr_agent` | `cai.agents.web3_gctr_agent` | Game-theoretic reasoning |
| `defi_bounty_judge` | `cai.agents.defi_bounty_judge` | DeFi-specific judging |

## Related Documentation

- [Planner Agent](planner.md) - Pre-Act planning methodology
- [Critic Agent](critic.md) - GPTLens-style review
- [Skeptic Agents](skeptics.md) - Adversarial denial layer
- [Manager Agents](managers.md) - Specialized analysis
- [Synthesis Agents](synthesis.md) - PoC generation
- [Aegis Ensemble](../patterns/aegis_ensemble.md) - Multi-agent coordination

## References

- [GPTLens Paper](https://arxiv.org/abs/2310.09099) - LLM-Powered Smart Contract Vulnerability Detection
- [Pre-Act Paper](https://arxiv.org/abs/2402.11534) - Multi-Step Planning and Reasoning Improves Acting
- [CAI Paper](https://arxiv.org/pdf/2504.06017) - An Open, Bug Bounty-Ready Cybersecurity AI
