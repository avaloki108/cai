# Judge Gate Pipeline (Hunter → Judge → PoC)

This pipeline keeps the **Hunter** creative and expansive while a separate **Judge Gate** stage ruthlessly filters candidate findings before any are promoted to submission or PoC. Only issues that pass the Judge as **EXPLOITABLE – BOUNTY ELIGIBLE** go to the PoC Builder.

## Why separate Hunter and Judge?

- **Hunter**: Finds suspicious patterns, edge cases, invariants to test; generates **many** candidate issues.
- **Judge**: Answers "Does this exploit work *now*, in current code?", "Show me the exact call sequence", "If mitigated, kill it."
- **PoC Builder**: Writes Foundry tests / minimal tx sequences only for **survivors**.

Making the Hunter act like a judge slows discovery. A dedicated Judge Gate prevents "HIGH-001 syndrome" (beautiful theory, zero payout).

## Pipeline phases

| Phase | Agent / role | Output |
|-------|----------------|--------|
| **A – Hunter** | `web3_bug_bounty_agent` (creative, expansive) | `candidates.json` (CANDIDATES_JSON) |
| **B – Judge Gate** | `defi_bounty_judge_agent` | `verdicts.json` (only EXPLOITABLE promoted) |
| **C – PoC Builder** | `retester_agent` or PoC tools | Foundry tests / tx sequences for EXPLOITABLE only |

## Contract between agents

### Hunter output (candidates)

When the Hunter is run for this pipeline, it must output candidates in this shape (label: **CANDIDATES_JSON**):

```json
{
  "candidates": [
    {
      "title": "...",
      "hypothesis": "...",
      "affected_code": ["..."],
      "suspected_attack": ["..."]
    }
  ]
}
```

See [system_web3_bug_bounty.md](../src/cai/prompts/system_web3_bug_bounty.md) (Judge Gate Pipeline Output) for field details.

### Judge output (verdicts)

The Judge evaluates each candidate and returns exactly one verdict per candidate:

- **EXPLOITABLE – BOUNTY ELIGIBLE** → promote to PoC
- **NOT EXPLOITABLE – ALREADY MITIGATED**
- **THEORETICAL / DESIGN RISK ONLY**
- **INVALID – NO REAL ATTACK PATH**

**Rule**: If the Judge cannot provide a **concrete call sequence** with **named functions** and **state preconditions**, it must return **INVALID – NO REAL ATTACK PATH**.

### Wiring in CAI

1. **Parallel pattern**: Use `web3_hunter_judge_poc_pattern` (Hunter lane(s) + Judge lane + PoC lane). Run the Hunt; then pass the Hunter’s CANDIDATES_JSON to the Judge (e.g. paste into Judge’s prompt). Judge outputs verdicts; use only EXPLOITABLE for PoC.
2. **agents.yml**: Add a Judge agent entry so it appears in parallel mode:
   ```yaml
   parallel_agents:
     - name: web3_bug_bounty_agent
       prompt: "ROLE: Hunter. Output CANDIDATES_JSON when you have candidate findings."
     - name: defi_bounty_judge_agent
       prompt: "ROLE: Judge Gate. You will receive candidates JSON. Output verdicts; only EXPLOITABLE go to PoC."
     - name: retester_agent
       prompt: "ROLE: PoC Builder. Build Foundry tests only for issues marked EXPLOITABLE – BOUNTY ELIGIBLE."
   ```
3. **Sequential (manual or script)**: Run Hunter → save `candidates.json` → run Judge with that file as input → save `verdicts.json` → run PoC Builder only on EXPLOITABLE entries.

## Quick reference

- **Judge prompt**: [system_defi_bounty_judge.md](../src/cai/prompts/system_defi_bounty_judge.md)
- **Judge agent**: `defi_bounty_judge_agent` in `src/cai/agents/defi_bounty_judge.py`
- **Hunter output contract**: "Judge Gate Pipeline Output" in [system_web3_bug_bounty.md](../src/cai/prompts/system_web3_bug_bounty.md)
