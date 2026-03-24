# Web3 Security Workflow Overview

CAI supports three distinct Web3 hunt workflows. Pick the one that matches your goal and evidence requirements.

## Workflow Contracts

| Mode | Entrypoint | Contract | Output |
| --- | --- | --- | --- |
| Interactive | `/hunt <path>` | Agent-led exploration with `web3_bug_bounty_agent` | Candidate findings and analysis conversation |
| Deterministic | `EliteWeb3Pipeline.run(target)` | Fixed stage order with deterministic report schema | Structured report with stage metrics and verdicts |
| Judge-gated | `web3_hunter_judge_poc_pattern` | Hunter -> Judge -> PoC handoff contract | Verdict-focused triage; only exploitable findings move to PoC |

## Mode Selection Guidance

- Use **Interactive** mode when you need broad exploration and hypothesis generation.
- Use **Deterministic** mode when you need reproducible stage-by-stage outputs and metrics.
- Use **Judge-gated** mode when your bar is bounty acceptance and exploitability proof.

## Deterministic Pipeline

`EliteWeb3Pipeline` (`src/cai/web3/pipeline.py`) executes:

1. Discovery (Slither + precision signals)
2. Risk Prioritization
3. Skeptic Gate
4. Fork Exploit Validation
5. Formal-like Invariant Gate

Report outputs include:

- `mode_contract` (how modes map to entrypoints)
- `summary` (critical/verified counts + exploitability breakdown)
- `quality_metrics` (stage input/output/rejections + PoC conversion rate)
- `findings` and `verified_findings` with exploitability verdict fields

## Judge Verdict Standard

Judge-mode verdicts are:

- `EXPLOITABLE – BOUNTY ELIGIBLE`
- `NOT EXPLOITABLE – ALREADY MITIGATED`
- `THEORETICAL / DESIGN RISK ONLY`
- `INVALID – NO REAL ATTACK PATH`

See `docs/judge_gate_pipeline.md` for candidate and verdict handoff formats.

## Practical Entry Points

```bash
# Interactive mode
cai
CAI> /hunt ./contracts

# Pattern-driven judge mode
CAI> /agent web3_hunter_judge_poc_pattern
```

Programmatic deterministic mode:

```python
from cai.web3.pipeline import EliteWeb3Pipeline

report = await EliteWeb3Pipeline().run("./contracts/Vault.sol")
```

## Web3 Plugin Runner

Web3 hunting now includes a policy-governed plugin runner surface:

- Agent tools: `list_web3_plugins`, `describe_web3_plugin`, `run_web3_plugin`
- REPL path: `/hunt plugins list|describe|run`
- Policies: `safe`, `balanced`, `aggressive`
- Controls: `--allow-aggressive`, `--dry-run`, `--timeout`

Example:

```bash
CAI> /hunt plugins list
CAI> /hunt plugins describe false_positive_filter
CAI> /hunt plugins run false_positive_filter --args '{"findings":[]}' --policy safe --dry-run
```

MCP exposure uses a dedicated stdio server:

```bash
CAI> /mcp load stdio web3tools python -m cai.mcp.web3_tools_server
CAI> /mcp add web3tools web3_bug_bounty_agent
```

Plugin exposure is intentionally scoped by surface (agent vs MCP). A registered plugin is not automatically exposed everywhere.

For step-by-step AI-agent instructions, see `docs/agents/web3/ai_agent_tool_runner_guide.md`.
