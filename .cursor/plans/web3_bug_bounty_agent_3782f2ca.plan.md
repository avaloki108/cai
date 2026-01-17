---
name: Web3 Bug Bounty Agent
overview: Create a comprehensive web3 bug bounty auditing agent with tiered/game-theoretic scope prioritization, leveraging existing security tools as sensors while adding custom orchestration and attack-graph reasoning for multi-step exploit discovery.
todos:
  - id: create-agent
    content: Create src/cai/agents/web3_bug_bounty.py with all web3 tools + custom enhancements
    status: pending
  - id: create-prompt
    content: Create src/cai/prompts/system_web3_bug_bounty.md with tiered game-theoretic methodology
    status: pending
  - id: create-attack-graph
    content: Create src/cai/tools/web3_security/enhancements/attack_graph.py for attack graph construction
    status: pending
  - id: create-cross-contract
    content: Create src/cai/tools/web3_security/enhancements/cross_contract.py for cross-contract analysis
    status: pending
  - id: create-exploit-scorer
    content: Create src/cai/tools/web3_security/enhancements/exploit_scorer.py for game-theoretic scoring
    status: pending
  - id: create-orchestrator
    content: Create src/cai/tools/web3_security/enhancements/multi_tool_orchestrator.py for tool aggregation
    status: pending
  - id: create-pattern
    content: Create src/cai/agents/patterns/web3_comprehensive.py parallel pattern
    status: pending
  - id: update-init
    content: Update src/cai/tools/web3_security/__init__.py to export new enhancement tools
    status: pending
  - id: register-agent
    content: Ensure agent is discoverable via CAI's agent factory system
    status: pending
isProject: false
---

# Web3 Bug Bounty Auditing Agent

## Architecture Overview

The agent follows CAI's architecture (Agents/Tools/Handoffs/Patterns/Guardrails) with a **tiered game-theoretic approach**:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Web3 Bug Bounty Agent                         │
├─────────────────────────────────────────────────────────────────┤
│  Game-Theoretic Prioritization Layer (G-CTR inspired)           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Attack Graph │  │ Payoff/Effort│  │ Strategic    │          │
│  │ Construction │  │ Scoring      │  │ Digest       │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│  Tiered Attack Surface Exploration                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ Tier 1     │  │ Tier 2     │  │ Tier 3     │                │
│  │ Contract + │─▶│ Economic + │─▶│ Frontend + │                │
│  │ Protocol   │  │ Oracle     │  │ Infra      │                │
│  └────────────┘  └────────────┘  └────────────┘                │
├─────────────────────────────────────────────────────────────────┤
│  Existing Tools (Sensors)           Custom Enhancements         │
│  - Slither (static)                 - Attack graph builder      │
│  - Mythril (symbolic)               - Cross-contract analyzer   │
│  - Echidna/Medusa (fuzzing)         - Economic invariant check  │
│  - Securify (verification)          - Exploit chain scorer      │
│  - Certora (formal)                 - Multi-tool orchestrator   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Files to Create/Modify

### 1. New Agent: `src/cai/agents/web3_bug_bounty.py`

The main agent file that:

- Imports all existing web3 security tools from `cai.tools.web3_security`
- Imports new custom enhancement tools
- Uses the specialized web3 bug bounty system prompt
- Includes guardrails for safe operation

Key structure based on existing [`bug_bounter.py`](src/cai/agents/bug_bounter.py):

- Same tool loading pattern
- Same guardrails integration
- New specialized instructions

### 2. System Prompt: `src/cai/prompts/system_web3_bug_bounty.md`

Comprehensive prompt with:

- **Tiered methodology** (Tier 1 → 2 → 3)
- **Game-theoretic prioritization** guidance
- **Multi-tool orchestration** workflow
- **False positive filtering** (critical for credibility)
- **Exploit chain reasoning** instructions

### 3. Custom Enhancement Tools: `src/cai/tools/web3_security/enhancements/`

New tools that add reasoning on top of existing sensors:

- **`attack_graph.py`** - Build attack graphs from tool outputs
  - `build_attack_graph(findings, contract_code)` - Construct graph from findings
  - `find_exploit_paths(graph, target)` - Identify viable exploit chains
  - `score_path_payoff(path)` - Game-theoretic payoff estimation

- **`cross_contract.py`** - Cross-contract analysis
  - `analyze_contract_interactions(contracts)` - Map inter-contract calls
  - `find_economic_invariants(protocol)` - Identify invariant assumptions
  - `check_invariant_violations(findings)` - Cross-reference with findings

- **`exploit_scorer.py`** - Exploit viability scoring
  - `score_exploit_viability(finding, context)` - Payoff vs effort calculation
  - `rank_findings_by_exploitability(findings)` - Strategic prioritization
  - `estimate_attacker_cost(exploit_path)` - Cost estimation

- **`multi_tool_orchestrator.py`** - Tool result aggregation
  - `aggregate_tool_results(results)` - Normalize and combine outputs
  - `correlate_findings(findings_list)` - Find related findings across tools
  - `generate_strategic_digest(aggregated)` - Create prioritized action plan

### 4. Parallel Pattern: `src/cai/agents/patterns/web3_comprehensive.py`

A pattern for comprehensive web3 auditing:

- **Discovery agent**: Uses static + symbolic tools
- **Fuzzing agent**: Runs Echidna/Medusa campaigns
- **Triage agent**: Validates and scores findings
- **Reporting agent**: Consolidates and prioritizes

### 5. Register Agent in `src/cai/agents/__init__.py`

Add the new agent to the available agents list.

---

## Tiered Methodology (Prompt Design)

### Tier 1: Contract + Protocol Logic (Highest ROI)

- Static analysis with Slither (detectors, human-summary)
- Symbolic execution with Mythril (reachability, path constraints)
- Property-based fuzzing with Echidna/Medusa
- Formal verification with Certora (invariants)
- Focus: reentrancy, access control, upgradeability, initialization

### Tier 2: Economic + Oracle + Integration

- Oracle manipulation analysis
- Flash loan attack vectors
- Cross-contract economic invariants
- MEV/sandwich attack surfaces
- Liquidation path analysis
- Focus: price manipulation, economic griefing, arbitrage

### Tier 3: Frontend + Infrastructure

- Wallet connection flows
- Approval UX vulnerabilities
- RPC trust assumptions
- CI/CD pipeline risks
- Dependency supply chain
- Focus: phishing vectors, key management, deployment security

---

## Game-Theoretic Prioritization

Inspired by G-CTR from the research paper:

- **Attack Graph**: Build from tool findings + manual analysis
- **Payoff Scoring**: `payoff = severity * likelihood / effort`
- **Strategic Digest**: Prioritized action list for agent
- **Adaptive Exploration**: Expand scope based on findings

---

## Integration Points

- **Existing tools**: All 35+ tools from [`web3_security/__init__.py`](src/cai/tools/web3_security/__init__.py)
- **Validation tools**: `validate_finding`, `filter_false_positives`
- **Guardrails**: Input/output security from [`guardrails.py`](src/cai/agents/guardrails.py)
- **Handoffs**: Can delegate to specialized sub-agents (retester, reporting)