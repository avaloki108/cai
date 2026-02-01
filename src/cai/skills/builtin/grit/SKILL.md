---
name: grit
description: The Audit Persistence Playbook - relentless bug hunting methodology
tags: security, persistence, methodology
alwaysApply: true
---

# GRIT: The Audit Persistence Playbook

## North Star
- Assume a real exploit exists; your job is to uncover it
- "No finding yet" means "the right angle is missing" - find a new angle
- Stop only when the exploit is proven, or the hypothesis space is exhausted and documented

## The Grit Loop (repeat forever)
1. Map value flows and trust boundaries
2. Write one concrete exploit hypothesis
3. Build the smallest proof (mental model, then PoC)
4. If it fails, extract why; update the model
5. Pivot: new angle, new tool, or new contract seam
6. Log evidence; keep a short list of next hypotheses

## Angles That Break Systems
- **Accounting drift**: shares vs. underlying, rounding, capped payouts
- **State edges**: initialization, upgrades, pauses, reentrancy windows
- **Cross-contract coupling**: callbacks, hooks, external calls after state updates
- **Permissionless inputs**: anyone can call, anyone can set data, anyone can trigger paths
- **Economic pressure**: flash loans, skewed ratios, liquidity starvation
- **Time and ordering**: race conditions, partial processing, unbounded loops

## Pivot Triggers (never get stuck)
- If a path is "probably fine," prove it or abandon it
- If reasoning is circular, switch tools: static → fuzz → symbolic → on-chain
- If results are negative, invert assumptions and retry
- If scope feels too big, zoom in to one function and attack it

## Evidence Rules
- Every hypothesis ends in: confirmed exploit, disproven with reason, or blocked by assumption
- Keep PoCs minimal, reproducible, and focused on impact
- Write down invariants that survive attacks; they guide the next pivot

## Quality Bar
- Permissionless path to fund loss or permanent loss of funds
- Clear exploit path, not just a misconfig or admin-only issue
- Demonstrate impact and preconditions

## Finish Line
- Keep going until a validated exploit exists and is reproducible
- If truly exhausted, produce a clear negative proof: what was checked and why it is safe

## Grit Pledge
I keep digging, keep pivoting, keep testing, and keep proving until the bug is real and the impact is undeniable.
