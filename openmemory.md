# CAI — OpenMemory Project Guide

Living index of the `avaloki108/cai` project. Updated as the codebase evolves.

## Overview

CAI (Cybersecurity AI) is a lightweight, open-source framework for building
bug bounty-ready AI agents. It targets semi-autonomous security testing with
human-in-the-loop oversight.

## Architecture

8 pillars: **Agents, Tools, Handoffs, Patterns, Turns, Tracing, Guardrails, HITL**.

```
CLI/REPL → Agent Factory → CAI Runner (turns/interactions)
    → Agent / Pattern → Tools + Extensions → Guardrails / Tracing / HITL
```

### Key entrypoints

| Path | Responsibility |
|------|----------------|
| `src/cai/cli.py` | CLI entrypoint, agent boot, REPL loop |
| `src/cai/sdk/agents/run.py` | Runner — turn/interaction loop |
| `src/cai/agents/factory.py` | Agent discovery & factory |
| `src/cai/agents/__init__.py` | Agent registry |
| `src/cai/web3/pipeline.py` | Deterministic Web3 audit pipeline |
| `src/cai/agents/defi_bounty_judge.py` | Judge-gate agent |
| `src/cai/core/finding.py` | Canonical `Finding` data model |

### Web3 audit flow

Two modes, both running through CAI Runner:

1. **Deterministic pipeline** (`EliteWeb3Pipeline`):
   Discovery → Risk Queue → Skeptic Gate → Fork Exploit → Formal
2. **Judge-gated bounty** (Hunter → Judge → PoC):
   `web3_bug_bounty_agent` → `defi_bounty_judge_agent` → `retester_agent`

### Memory integration (Mem0 / OpenMemory)

Memory is accessed as a CAI extension layer:
- **Read** before planning/decision points (Phase 0 pre-flight, Phase 2 scoring)
- **Write** after validated outcomes (Phase 5 report, post-PoC)
- Project facts use `project_id`, user preferences use `user_preference=true`
- Config: `CAI_MEMORY`, `CAI_MEMORY_ONLINE`, `CAI_MEMORY_OFFLINE` env vars

## Components

| Component | Location | Notes |
|-----------|----------|-------|
| Web3 Bug Bounty Agent | `src/cai/agents/web3_bug_bounty.py` | 100+ tools, game-theoretic |
| DeFi Judge Agent | `src/cai/agents/defi_bounty_judge.py` | Exploitability gatekeeper |
| Elite Pipeline | `src/cai/web3/pipeline.py` | CAI-native, no web3_security_ai deps |
| Enhancement Tools | `src/cai/tools/web3_security/enhancements/` | Stage-mapped (0-5) |
| Bridge Analyzer | `src/cai/agents/bridge_analyzer.py` | Cross-chain vuln tools |
| MEV Analyzer | `src/cai/agents/mev_analyzer.py` | Sandwich/frontrun/backrun |
| Perpetuals Analyzer | `src/cai/agents/perpetuals_analyzer.py` | Funding/liquidation/margin |
| Composite Audit Pattern | `src/cai/agents/patterns/composite_audit.py` | HMAW + Adversarial + Ensemble |

## Patterns

- `agents.yml` drives parallel mode (auto-loaded at startup)
- Judge Gate pipeline: `docs/judge_gate_pipeline.md`
- Parallel patterns: `docs/multi_agent.md`

## User Defined Namespaces

- [Leave blank - user populates]
