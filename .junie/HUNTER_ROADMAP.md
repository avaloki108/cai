# Web3 Bug Bounty Hunter — Agent Capability Curriculum

This roadmap defines the learning and reasoning progression for the `web3_bug_bounty_hunter` agent. Instead of a simple task list, it is a **Curriculum** where each step builds the foundational reasoning power (Strategic, Logic, State, Economic) required to unlock more complex exploitation capabilities.

---

## Phase 1: Strategic Synthesis & Validation Foundation

### 1) [Infrastructure] Multi-Tool Orchestration & Deep Repo Context
- **Reasoning focus:** Strategic Correlation & Evidence Triage.
- **Milestone 1.1: Multi-Tool Evidence Fusion** — Implement `multi_tool_orchestrator.py` to cross-correlate Slither, Mythril, and Echidna findings.
- **Milestone 1.2: Protocol Auto-Detection** — Enhance `repo_context.py` to identify protocol type and map roles (Owner, Gov, Relayer).

**Capability Gained:** **Strategic Synthesis.** The agent gains the ability to triage raw tool outputs through the **Evidence Hierarchy** (Simulation > Invariant > Symbolic > Static), discarding noise and focusing on high-confidence hypotheses.
**Unlocks:** Targeted hunting in all subsequent phases.
**Why it must occur before later steps:** Without a unified "Strategic Digest," the agent is blinded by tool noise. It must be able to *verify* a simple static finding (Slither) using a higher-order tool (Mythril/Foundry) before it can be trusted with complex logic.

---

## Phase 2: EXPLOIT FEASIBILITY REASONING

- **Reasoning focus:** Monetization and Attacker Reachability Triage.
- **Feasibility dimensions** checked for every candidate finding:
  1. Attacker reachability (permissionless call path; no privileged key assumptions)
  2. Controllable inputs (price, role, callback, signature, timing)
  3. Value extraction path (how funds/value exit to the attacker EOA)
  4. Bounded capital requirement (static upper bound on capital/fees to trigger)

- **Milestone 1.3: Feasibility Triage Automation** — Implement `auto_score_finding` logic to detect reachability, inputs, extraction, and capital requirements automatically to prioritize findings in the `strategic_digest`.

**Capability Gained:** **EXPLOIT FEASIBILITY REASONING.** The agent estimates, without executing transactions or fork simulations, whether a hypothetical issue is monetizable given attacker reachability, controllable levers, a concrete extraction route, and a bounded capital need. This raises prioritization confidence while staying within the Evidence Hierarchy.
**Unlocks:** All specialized detectors by providing a pre-filter that discards non-monetizable or role-gated findings.
**Why it must occur before later steps:** Specialized detectors otherwise flood the agent with false positives. Feasibility gating eliminates cases with no permissionless path, no attacker-controlled inputs, no extraction route, or unrealistic/unbounded capital assumptions.

---

## Phase 3: Logic & Lifecycle State Modeling

**Feasibility Filter for this phase:** Reject upgrade/init and access-control alerts unless a permissionless caller can reach the sink now or via a non-privileged path, the attacker controls the relevant timing window, and there is a concrete extraction route (e.g., upgrade to malicious impl, seize privileged action). Capital need is minimal; prioritize those.

### 2) Upgradeability & Initialization Hardening
- **Reasoning focus:** Temporal State Analysis (Before vs. After).
- **Milestone 2.1: Proxy Pattern Discovery** — Identify UUPS, Transparent, Beacon, and Diamond patterns. — ✅ Completed
- **Milestone 2.2: Initialization State Checks** — Cross-verify deployment logs/state with implementation logic. — ✅ Completed

**Capability Gained:** **Temporal State Modeling.** The agent learns to reason about the delta between a contract's deployed state and its initialized state, identifying "windows of vulnerability."
**Unlocks:** Access control exploits (which are often rooted in initialization gaps).
**Why it must occur before later steps:** Initialization is the "Step 0" of contract state. If the agent cannot model how a contract starts, it cannot accurately model how that contract's permissions or logic evolve.

### 3) Access-Control and Role-Confusion Analysis
- **Reasoning focus:** Authority & Permission Mapping.
- **Milestone 3.1: Role Lattice Construction** — Map the hierarchy of Owner, Admin, and specialized roles. — ✅ Completed
- **Milestone 3.2: Privilege Escalation Detection** — Identify paths where low-privilege actors can reach high-privilege sinks. — ✅ Completed

**Capability Gained:** **Permission Lattice Modeling.** The agent gains a formal understanding of "Who" can do "What," moving beyond simple `onlyOwner` checks to complex DAO and multi-sig authority models.
**Unlocks:** Governance attacks and authorized-only economic exploits.
**Why it must occur before later steps:** Access control is the primary guardrail for all logic. Economic and governance exploits (Phases 4-5) are often just sophisticated ways to bypass or co-opt these permissions.

---

## Phase 4: External Authentication & Input Logic

**Feasibility Filter for this phase:** Keep only findings where an external adversary can actually supply or replay inputs without privileged keys, the attacker controls nonce/deadline/timing, and there exists an approval or fund-movement path that yields value extraction. Otherwise, downgrade as theoretical.

### 4) Signature Integrity & Cross-Chain Replay Protection
- **Reasoning focus:** Cryptographic Authentication Logic.
- **Milestone 4.1: Domain Separator Validation** — Check EIP-712 implementations for chainID and address binding. — ✅ Completed
- **Milestone 4.2: Nonce/Replay Analysis** — Model off-chain message state to find reuse vulnerabilities. — ✅ Completed

**Capability Gained:** **External Logic Authentication.** The agent learns to reason about off-chain authorization vs. on-chain execution, specifically how non-deterministic external inputs (signatures) transition contract state.
**Unlocks:** Bridge analysis and cross-chain protocol auditing.
**Why it must occur before later steps:** Signature logic introduces a "state" that exists outside the EVM (nonces, deadlines). Mastering this is a prerequisite for modeling the complex capital movements in DeFi.

### 5) Permit/Signature Misuse (EIP-2612/712) and Allowance Races
- **Reasoning focus:** Token Flow Authorization.
- **Milestone 5.1: Permit Flow Modeling** — Analyze `transferFrom` races and `permit` deadline exploits. — ✅ Completed
- **Milestone 5.2: Signature Malleability Triage** — Distinguish between theoretical malleability and exploitable fund loss.

**Capability Gained:** **Token Approval Flow Modeling.** The agent learns to model the primary mechanism of fund movement in DeFi: the approval/permit lifecycle.
**Unlocks:** Complex Vault and Lending exploits where fund-drain relies on signature misuse.
**Why it must occur before later steps:** Token approvals are the "gas" for most economic attacks. The agent must understand how funds are unlocked before it can model how they are stolen via accounting flaws.

---

## Phase 5: Systemic State & Flow Modeling

**Feasibility Filter for this phase:** Keep only invariant breaks that a permissionless actor can trigger using controllable levers (first-depositor, donation, price impact), that have a clear extraction route (redeem/withdraw/skim/fee accrual), and that admit a finite seed-capital bound. Otherwise, deprioritize.

### 6) ERC4626 Invariant Generation + Property Fuzzing
- **Reasoning focus:** Systemic Invariant Reasoning.
- **Milestone 6.1: Auto-Property Emission** — Generate Scribble/Echidna properties for vault accounting (TotalAssets vs. TotalShares).
- **Milestone 6.2: Inflation Attack Simulation** — Use fuzzer results to prove first-depositor and donation vulnerabilities.

**Capability Gained:** **Systemic State Modeling.** The agent moves from "Pattern Matching" to "Invariant Proving." It gains the ability to define what a protocol *must always do* and then attempt to break that rule.
**Unlocks:** Advanced Reentrancy and Economic attacks.
**Why it must occur before later steps:** Economic attacks are essentially very complex invariant violations. The agent cannot detect "Price Manipulation" if it doesn't first understand the "Price Invariant."

### 7) Advanced Reentrancy via Token Hooks and Cross-Function Callbacks
- **Reasoning focus:** Cross-Contract State Propagation.
- **Milestone 7.1: Hook Discovery** — Identify ERC777, ERC721 `onReceived`, and fee-on-transfer callback points.
- **Milestone 7.2: Cross-Function Reentrancy Graphing** — Map state changes that occur across different functions during a single callback.

**Capability Gained:** **Cross-Contract State Propagation.** The agent learns how external calls can change the state of the *calling* contract mid-transaction, breaking the "Check-Effects-Interactions" pattern across heterogeneous contracts.
**Unlocks:** Flash-loan exploits which rely on callback hooks for execution.
**Why it must occur before later steps:** Requires the Invariant Reasoning from Step 6 to identify when the protocol state is inconsistent during a callback. This is the bridge between simple code bugs and complex economic exploits.

---

## Phase 6: Game-Theoretic & Market Modeling (The "Final Bosses")

**Feasibility Filter for this phase:** Validate permissionless reachability (e.g., flash-loanable voting power or oracle control), attacker-timed snapshot/timelock windows, explicit extraction routes via privileged execution or mispriced accounting, and a bounded/estimable capital requirement relative to payoff; otherwise downgrade.

### 8) Flash-Loan-Assisted Governance Takeover Detection
- **Reasoning focus:** Capital-Weighted Logic & Quorum Modeling.
- **Milestone 8.1: Governance Path Simulation** — Model the path from flash-loan -> voting power -> proposal -> execution.
- **Milestone 8.2: Snapshot/Timelock Bypass** — Identify blocks where voting power can be manipulated before snapshots.

**Capability Gained:** **Capital-Weighted Logic Modeling.** The agent learns to reason about "Voting Power" and "Quorum" as fluid resources that can be flash-borrowed to seize protocol control.
**Unlocks:** Multi-pool economic attacks and protocol-wide insolvency modeling.
**Why it must occur before later steps:** Governance attacks combine Access Control (Roles), Invariants (Voting Weight), and Simulation (Flash Loans). It represents the synthesis of all previous reasoning capabilities.

### 9) Economic Invariants: MEV-Aware Oracles and Multi-Pool Economic Attacks
- **Reasoning focus:** Adversarial Market Modeling.
- **Milestone 9.1: Oracle/Price Logic** — Detect spot-price dependencies vs. TWAP (Thin liquidity/Same-block gaps).
- **Milestone 9.2: Multi-Pool Invariant Violations** — Simulate cross-pool price path attacks and transient insolvency.

**Capability Gained:** **Adversarial Market Modeling.** The agent reaches the peak of its curriculum, reasoning about the intersection of contract code, state invariants, and external market volatility (Liquidity depth, MEV, and Oracle lags).
**Unlocks:** Infinite-scale autonomous exploit discovery.
**Why it must occur before later steps:** This is the most complex form of reasoning. It assumes the agent can already model logic (Phase 2), authentication (Phase 3), and systemic state (Phase 4).

---

## Curriculum Success Metrics

1. **Reasoning Depth:** Moves from **Static Pattern Matching** (Phase 1) to **Adversarial Market Modeling** (Phase 5).
2. **Verification Power:** Every finding is pushed up the **Evidence Hierarchy** using the tools unlocked in Phase 1.
3. **Dependency Integrity:** Economic attacks are never attempted without prior Invariant and Access modeling.
4. **Autonomous Capability:** Each step reduces the agent's reliance on human-provided heuristics and increases its ability to generate its own exploitation proofs.
