# Architecture Overview

CAI focuses on making cybersecurity agent **coordination** and **execution** lightweight, highly controllable, and useful for humans. To do so it builds upon 8 pillars: `Agent`s, `Tools`, `Handoffs`, `Patterns`, `Turns`, `Tracing`, `Guardrails` and `HITL`.

```
                  ┌───────────────┐           ┌───────────┐
                  │      HITL     │◀─────────▶│   Turns   │
                  └───────┬───────┘           └───────────┘
                          │
                          ▼
┌───────────┐       ┌───────────┐       ┌───────────┐      ┌───────────┐
│  Patterns │◀─────▶│  Handoffs │◀────▶ │   Agents  │◀────▶│    LLMs   │
└───────────┘       └─────┬─────┘       └─────┬─────┘      └───────────┘
                          │                   │
                          │                   ▼
┌────────────┐       ┌────┴──────┐       ┌───────────┐     ┌────────────┐
│ Extensions │◀─────▶│  Tracing  │       │   Tools   │◀───▶│ Guardrails │
└────────────┘       └───────────┘       └───────────┘     └────────────┘
                                              │
                          ┌─────────────┬─────┴────┬─────────────┐
                          ▼             ▼          ▼             ▼
                    ┌───────────┐┌───────────┐┌────────────┐┌───────────┐
                    │ LinuxCmd  ││ WebSearch ││    Code    ││ SSHTunnel │
                    └───────────┘└───────────┘└────────────┘└───────────┘
```

If you want to dive deeper into the code, check the following files as a start point for using CAI:

```
cai
├── __init__.py
│
├── cli.py                        # Entrypoint for CLI
├── util.py                       # Utility functions
│
├── repl                          # CLI aesthetics and commands
│   ├── commands
│   └── ui
├── sdk                           # Agent runtime (Runner, turns, streaming)
│   └── agents
│       └── model
├── agents                        # Agent implementations
│   ├── one_tool.py               # One agent per file
│   ├── web3_bug_bounty.py        # Web3 audit agent
│   ├── defi_bounty_judge.py      # Judge-gate agent
│   └── patterns                  # Agentic patterns, one per file
│
├── core                          # Shared data models
│   └── finding.py                # Canonical Finding model
├── web3                          # Web3-specific orchestration
│   └── pipeline.py               # Deterministic audit pipeline
├── tools                         # Agent tools
│   ├── common.py
│   └── web3_security/            # Web3 security tool suite
│       └── enhancements/         # Stage-mapped reasoning tools
│
└── prompts                       # System prompt templates
```

For the full architecture reference including pillar definitions, pattern taxonomy, and HITL design, see [Architecture](../../cai_architecture.md).
