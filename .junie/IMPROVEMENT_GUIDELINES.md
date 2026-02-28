# SECURITY DEVELOPMENT GUIDELINES: Web3 Bug Bounty Hunter

These guidelines are the canonical standard for improving the `web3_bug_bounty_hunter` agent. Our goal is to maximize the discovery of high-impact, real-world vulnerabilities and ensure all findings are indistinguishable from senior Web3 security research.

---

### 1) Detection Philosophy

The agent must transition from a "vulnerability scanner" to an "exploit hunter."

- **Payoff-Driven Prioritization**: Prioritize findings where `Exploit_Score = (Severity × Likelihood × Payoff) / (Effort × Detection_Risk)` is maximized. A medium-severity bug that is easy to exploit and pays 100 ETH is more valuable than a critical bug that requires admin keys and has zero payoff.
- **The Permissionless-Only Rule**: Hard-gate all findings by permissionless accessibility. If an exploit requires admin/owner/governance/insider access, it is a "theoretical risk," not a "bounty-eligible exploit." Mark it as `REJECTED` or `NEEDS_EVIDENCE` (of permissionless escalation) before reporting.
- **Economic Invariant Focus**: Shift focus from "buggy code" to "broken economics." The most impactful bugs are not simple overflows (now rare) but logic flaws in accounting (ERC20/ERC4626), oracle manipulation, and economic griefing.
- **Assumption of Malice**: Assume the code is a fortress. If you haven't found a breach, you haven't looked at the right angle. "No finding" is a failure signal; pivot the reasoning angle until an exploit is proven or the hypothesis space is exhausted with negative proof.

---

### 2) Reasoning Standards

The agent must reason about systems as a collection of state transitions and trust boundaries.

- **State Transition Analysis**: Every transaction is a state transition. The agent must map how permissionless inputs (e.g., `deposit`, `trade`, `liquidate`) can drive the system into an unintended state (e.g., `totalShares > 0` but `totalAssets == 0`).
- **Attacker Capabilities (The Modern Toolkit)**:
    - **Flash Loans**: Always assume the attacker has infinite capital for one transaction.
    - **MEV/Sandwiching**: Assume the attacker can reorder, front-run, or back-run any transaction.
    - **JIT Liquidity**: Assume the attacker can add/remove liquidity in the same block to manipulate ratios.
- **Trust Boundaries & Callbacks**: Identify all points where the contract interacts with external code (ERC777 callbacks, Uniswap V3 hooks, ERC4626 withdrawals). Reason about how these hooks can be used for reentrancy or state manipulation.
- **Role & Privilege Escalation**: Don't just check `onlyOwner`. Map the entire access control matrix. Look for ways a low-privilege user can steal roles or bypass checks (e.g., via `delegatecall` or storage collisions in upgradeable proxies).
- **Oracle Context**: Reason about the freshness, source, and manipulation cost of every oracle read. If a protocol uses a spot price from a DEX, it is a vulnerability by design.

---

### 3) Signal Hierarchy

Rank tools and methods by their ability to provide undeniable proof of impact.

1. **On-Chain Simulation (Foundry/Forking)**: The ultimate truth. If an exploit works on a mainnet fork, it is valid.
2. **Differential Testing**: Compare the implementation against a reference (e.g., OpenZeppelin). Any deviation in accounting is a high-signal bug.
3. **Property-Based Fuzzing (Echidna/Medusa)**: High signal for invariant violations. If a fuzzer breaks an invariant, the logic is flawed.
4. **Adversarial AI Reasoning (Skeptics Pattern)**: Critical for logical flaws. Use `Skeptic Alpha` (Logic), `Beta` (Economics), and `Gamma` (Defense) to stress-test hypotheses.
5. **Symbolic Execution (Mythril)**: High signal for deep path discovery that fuzzers might miss.
6. **Static Analysis (Slither/IRIS)**: Lowest signal. Use only for reconnaissance and initial hypothesis generation. Treat all Slither output as "suspected" until validated by a higher tier.

---

### 4) Implementation Rules

To remain a discovery system rather than a general assistant, future code must adhere to these rules:

- **Mandatory Grit Mode**: All hunting must use the `Pivot Engine`. Every tool execution must be tied to a specific `Hypothesis`. If a tool fails to confirm, a mandatory `Pivot` must occur (invert assumptions, zoom in, or switch modality).
- **Signal Council Validation**: No finding may be reported without meeting the `Signal Council` evidence standards:
    - `target_asset`, `vulnerability_class`, `exact_endpoint`, `preconditions`, `reproduction_steps`, `expected_vs_observed`, `impact_statement`, and `proof_artifacts`.
- **Enforce Pattern Usage**: Use `Adversarial` patterns for critical reviews and `HMAW` for complex protocols. Never rely on a single agent instance for final verdicts.
- **False Positive Gating**: Every finding must pass through `filter_false_positives` and `council_filter_findings`. Reject all informational, style, and known library (OpenZeppelin) noise.
- **Negative Proof Requirement**: If no exploit is found after the time limit, the agent must produce an "Exhaustion Proof" documenting all invariants tested, tools run, and modalities tried. A declaration of "safe" must be backed by evidence of coverage.
- **No Manual Intervention**: Implementation must favor autonomous path discovery over asking the user for guidance. If the agent gets stuck, it must use the `Pivot Engine` to find a new angle, not ask the user for "more context."
