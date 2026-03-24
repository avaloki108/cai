# Improvement Plan: High-Accuracy Vulnerability Discovery for Competitive Audits

**Source of truth:** [.cursor/architecture_review.md](.cursor/architecture_review.md)

**Goal:** Transform the CAI framework from a tool-orchestrating hunt system into a **methodology-driven** vulnerability discovery system suitable for competitive audit contests (Cantina, Code4rena). Focus is on **reasoning rigor**, **proof-of-exploit**, **multi-gate validation**, and **research-team structure**—not generic refactoring.

---

## 1) Reasoning Upgrades

### 1.1 Adversarial verification loops

**Current gap (from review):** Pipeline skeptic is rule-based only; Judge is single-shot; no red team that tries to disprove the attack path.

**Upgrade:**

- **Structured skeptic loop:** For every candidate that passes the Judge gate, run a dedicated **disproof agent** (separate from Judge) whose only job is to try to invalidate the finding: "Given this attack path and preconditions, find a reason it cannot work (guard, modifier, state requirement, economic infeasibility)." The finding survives only if the disproof agent fails to produce a valid counter-argument within a bounded number of attempts.
- **Dual-judge consistency:** Run the exploitability Judge twice (or with two distinct prompts/models); promote to PoC only if both return EXPLOITABLE with consistent attack_path semantics (same entrypoints and preconditions). Divergence triggers human review.
- **Pipeline integration:** Wire adversarial skeptics (skeptic_alpha/beta/gamma or equivalents) into `EliteWeb3Pipeline` as a **mandatory** stage between risk prioritization and exploit stage; findings must survive at least one LLM skeptic before fork test.

### 1.2 Proof-of-exploit requirement

**Current gap:** Fork test is template-based; no Finding object (location, call_trace, state_variables) drives test generation; "exploit succeeded" can be from a generic stub.

**Upgrade:**

- **Finding-specific PoC contract:** Define a **ProofOfExploit** artifact: a runnable test (Foundry/Forge) that (a) is generated from the canonical Finding (contract, function_name, location, call_trace, state_variables), (b) encodes the Judge-approved attack_path as concrete calls, (c) contains an explicit **impact assertion** (e.g. balance delta, invariant violation) that fails before the fix and passes after. No finding is marked "verified" without this artifact.
- **Mandatory PoC run after Judge:** Judge EXPLOITABLE → auto-invoke exploit engineer to produce ProofOfExploit → run test on mainnet fork → only if test passes (and impact assertion holds) promote to report. If PoC fails, route back to attacker modeler or disproof agent with failure reason.
- **Impact assertion as gate:** Every verified finding must have a machine-checkable statement (e.g. `assertEq(victimBalanceAfter, 0)` or `assertLt(poolReserve, initialReserve)`); the pipeline rejects findings whose PoC does not include and satisfy such an assertion.

### 1.3 Economic reasoning

**Current gap:** Profit = 1.0 - gas_cost; no flash-loan or MEV simulation; economic viability is heuristic.

**Upgrade:**

- **Attacker capability model:** Before labeling a finding economically viable, the system must explicitly model: (a) capital required (own funds vs flash loan vs MEV bundle), (b) gas cost on the actual call path, (c) slippage/liquidity constraints if the attack touches AMMs or oracles, (d) whether the attack is one-shot vs multi-block. Output: "Economically viable under assumption X" or "Not viable because Y."
- **Economic gate in pipeline:** Add an **economic viability check** stage (after skeptic, before or after exploit stage): an agent or tool that consumes attack_path + preconditions + protocol context and outputs viable / not_viable / needs_manual_review with reasoning. Findings marked not_viable are not reported as high/critical.
- **Contest-specific calibration:** For Cantina/Code4rena, align economic reasoning with judge expectations (e.g. "attacker has no prior position," "flash loan available up to pool size"); make these assumptions configurable and visible in the report.

### 1.4 Invariant derivation

**Current gap:** formal_stage sets invariant_broken by hardcoded vulnerability_type; no protocol-level invariant definition or Echidna/Certora driving accept/reject.

**Upgrade:**

- **Invariant researcher role:** Dedicated agent/tool that (a) derives protocol invariants from code and docs (e.g. "totalSupply == sum(balances)", "collateral >= debt for all positions"), (b) produces machine-checkable forms (Scribble, Echidna, or Certora specs), (c) runs invariant tests; only findings that **violate a stated invariant** (with a failing run) can claim "invariant broken."
- **No invariant_broken by type alone:** Remove the hardcoded list (reentrancy, overflow, precision_loss, oracle-manipulation) as the sole basis for invariant_broken. Replace with: invariant_broken = True only when (i) an invariant is explicitly stated and (ii) a test or proof shows it is violated by the finding's attack path.
- **Wire Echidna/Medusa/Certora into pipeline:** Invariant researcher output (specs + run results) becomes an input to the pipeline; findings that do not map to a violated invariant cannot be elevated to "critical" on invariant grounds.

### 1.5 Attacker capability modeling

**Current gap:** No explicit model of what the attacker can do (calls, capital, ordering); Judge and tools assume "permissionless" but do not formalize it.

**Upgrade:**

- **Attacker model document:** For each audit target, produce an **attacker capability spec**: (a) entrypoints the attacker can call (public/external, no privilege), (b) resources (flash loan size, own balance, MEV tools), (c) constraints (no admin keys, no prior protocol position unless stated), (d) time (single tx vs multi-block). Recon and attacker modeler agents populate this; all subsequent reasoning (Judge, economic check, PoC) must stay within this spec.
- **Attack path validation against model:** Judge and exploit engineer must only produce attack paths that use entrypoints and resources allowed by the attacker model; otherwise the finding is downgraded to "assumes privileged access" or "theoretical."
- **Contest alignment:** Attacker model defaults should match common contest rules (e.g. "EOA or contract, no special privileges") and be overridable per contest.

---

## 2) False Positive Filter: Multi-Gate Verification Pipeline

**Design:** A finding is **reported** only if it survives a fixed sequence of independent validations. No single agent or tool can promote a finding to report by itself.

### Gate sequence (all must pass)

1. **Tool evidence gate:** Finding must be traceable to at least one static/dynamic tool output (Slither, Mythril, Echidna, etc.) with location and type. No "I think there's a bug" without tool evidence. (Satisfies architecture review principle: single source of truth for tool output.)

2. **Pattern/FP filter gate:** Existing validate_finding + enhancement validation + council run as today, but with **auditable rules only**: regex patterns, TOOL_RELIABILITY, confidence thresholds. Findings that match known FP patterns or fall below threshold are dropped. Document every rule that dropped a finding.

3. **Exploitability gate (Judge):** Judge requires concrete call sequence, preconditions, impact. Verdict must be EXPLOITABLE; INVALID / THEORETICAL / MITIGATED → drop. Optionally dual-judge for consistency.

4. **Adversarial gate (disproof):** Disproof agent attempts to invalidate the finding. If it produces a valid counter-argument (with evidence), the finding is dropped or sent to "Needs Manual Review." Only findings that survive disproof attempts proceed.

5. **Economic viability gate:** Attacker modeler / economic check outputs viable or needs_manual_review. not_viable → do not report as high/critical (can be reported as medium/low with caveat).

6. **Proof-of-exploit gate:** Finding-specific PoC must be generated and run; impact assertion must hold on fork. If PoC fails or cannot be generated from the finding, do not mark as verified; drop or downgrade.

7. **Invariant gate (if "invariant broken" claimed):** If the finding claims an invariant violation, a stated invariant and a failing run (Echidna/Certora/property test) must exist. Otherwise do not set invariant_broken.

### Implementation note

- Each gate is a **stage** in the pipeline; findings carry a **gate state** (passed/failed/dropped) per gate. The pipeline can short-circuit (e.g. after Judge INVALID, do not run disproof). Report only findings that have passed all applicable gates.
- Human review is required for any finding that passes Judge but fails PoC, or that the disproof agent flags as "ambiguous."

---

## 3) Exploit Discovery Strategy: From Pattern-Matching to Hypothesis Testing

**Current state:** Tools (Slither, Mythril) produce raw findings; Hunter interprets and may over-claim; no enforced structure for "what we are trying to prove."

**Transformation:**

### Hypothesis-first workflow

1. **Hypotheses from recon and invariants:** Recon analyst and invariant researcher produce (a) attack surface map (entrypoints, trust boundaries, value flows), (b) stated invariants. From these, the system **generates explicit hypotheses** (e.g. "An attacker can drain pool by violating invariant I1," "Reentrancy in function F allows double-withdraw"). Hypotheses are the unit of work; tools are used to **test** hypotheses, not the other way around.

2. **One hypothesis → one proof or disproof:** For each hypothesis: (i) assign tools (static/symbolic/fuzz) to gather evidence for or against; (ii) if evidence supports, produce attack path and send to Judge; (iii) if Judge says EXPLOITABLE, produce PoC and run; (iv) if PoC fails, either refine hypothesis (e.g. cross-function reentrancy) or mark hypothesis disproven. No finding is reported without a hypothesis that was tested and not disproven.

3. **Pivot as hypothesis refinement:** PivotEngine (or equivalent) drives **hypothesis** pivots: "Reentrancy in F failed → try read-only reentrancy," "Oracle manipulation failed → try TWAP window." The run loop tracks hypotheses and their status (pending, supported, disproven, PoC passed); "no findings" is only valid when a defined hypothesis set is exhausted or time-bounded.

4. **Tool output as evidence only:** Tool outputs (Slither, Mythril, etc.) are **evidence** for or against a hypothesis. They are parsed into structured form (e.g. map to Finding schema) and attached to the hypothesis. The report never lists "Slither said X" as the finding; it lists "Hypothesis H: ... ; evidence: Slither (location L), PoC (impact assertion A)."

### Contest alignment

- Hypothesis set can be seeded from contest scope (e.g. "in-scope: lending, oracles; out-of-scope: governance"). This keeps the hunt bounded and reduces noise.

---

## 4) Agent Responsibilities: Research Team Structure

Redesign agent roles into a **research team** that mirrors how competitive audit teams operate. Each role has clear inputs, outputs, and handoffs.

| Role | Responsibility | Inputs | Outputs | Handoffs |
|------|-----------------|--------|---------|----------|
| **Recon analyst** | Map attack surface, entrypoints, value flows, dependencies; produce attacker capability spec (what attacker can call, with what resources). | Target repo, contest scope/rules. | Attack surface doc, attacker capability spec, list of entrypoints and trust boundaries. | → Invariant researcher, Attacker modeler, Exploit engineer. |
| **Invariant researcher** | Derive protocol invariants from code/docs; produce machine-checkable specs; run Echidna/Certora/Medusa; report which invariants hold or fail. | Recon output, target code. | Invariant specs, test results (hold/fail), mapping of code regions to invariants. | → Hypothesis generation, Exploit engineer (for invariant violation claims). |
| **Attacker modeler** | Maintain attacker capability model; for each candidate attack path, check consistency with model; produce economic viability assessment (capital, gas, slippage). | Recon output, Judge attack_path, protocol context. | Attacker model doc, per-finding viability: viable / not_viable / needs_manual_review + reasoning. | → Judge (constrain paths), Economic gate, Report. |
| **Exploit engineer** | Turn Judge-approved attack paths into finding-specific PoCs; generate and run ProofOfExploit tests; assert impact; report pass/fail. | Finding (with location, call_trace), Judge attack_path and preconditions, invariant researcher output (if invariant claim). | ProofOfExploit artifact, run result (pass/fail), impact assertion result. | → Disproof agent (on failure), Report (on pass). |
| **Skeptic / disproof agent** | Try to disprove findings: challenge assumption chain, look for guards/mitigations, try to show attack path is infeasible or wrong. | Candidate finding, attack_path, preconditions, code context. | Disproof result: disproven (with reason) / not_disproven / needs_manual_review. | → Pipeline (drop or promote finding), Human (on ambiguous). |

### Orchestration

- **Hypothesis coordinator (or Planner):** Generates hypotheses from recon + invariants; assigns work to tools and agents; tracks hypothesis status; triggers pivots. Can be implemented as an enhanced Planner or a small dedicated agent.
- **Judge (existing, tightened):** Consumes only candidates that have tool evidence and conform to attacker model; outputs EXPLOITABLE only with concrete attack_path; handoff to Exploit engineer and Disproof agent.
- **No single "Hunter" that does everything:** Current web3_bug_bounty_agent is split into recon, hypothesis-driven tool use, and coordination; discovery is hypothesis-led, not tool-dump-led.

### Mapping from current codebase

- Recon analyst: new or from web3_discovery_agent + parts of planner.
- Invariant researcher: new; uses Echidna/Medusa/Certora tools; outputs specs and results.
- Attacker modeler: new or from manager_access + economic reasoning.
- Exploit engineer: exploit_synthesizer + poc_generator + retester, but with **finding-specific** PoC generation (requires Passing Finding object into generate_fork_test and impact assertions).
- Skeptic / disproof: skeptic_alpha/beta/gamma promoted to mandatory pipeline stage with explicit "try to disprove" instruction; or a single disproof agent.

---

## 5) Measurable Success Criteria

Metrics that determine whether the system is actually improving toward contest-ready quality. All should be measured per run or per audit and tracked over time.

### 5.1 Exploit reproducibility

- **Metric:** % of reported findings that have a PoC that (a) compiles, (b) runs on the designated fork, (c) satisfies the stated impact assertion.
- **Target:** 100% of "verified" findings. No finding in the report without a passing PoC.
- **Measurement:** Automated: after report generation, re-run all PoCs; count pass/fail. Track trend.

### 5.2 Signal-to-noise ratio

- **Metric:** Ratio (true positives) / (true positives + false positives) where true positive = finding accepted by contest judge or by human auditor; false positive = finding rejected as invalid/duplicate/theoretical.
- **Target:** Improve over baseline (current system); aim for ≥ 0.7 for "high/critical" tier in a sampled contest or internal eval.
- **Measurement:** Run on past contest codebases with known outcomes; or submit to a contest and use judge feedback. Internal: human label a sample of reports as accept/reject.

### 5.3 Duplicate reduction

- **Metric:** % of reported findings that are duplicates (same root cause, same fix) of another finding in the same report or in a known set.
- **Target:** 0% duplicates in final report; dedupe before report.
- **Measurement:** Dedupe step (by root cause / location / fix); count duplicates merged. Track "findings before dedupe" vs "after."

### 5.4 Report acceptance likelihood

- **Metric:** For findings submitted to a contest (or to an internal judge): % accepted (paid or validated) vs rejected (invalid, duplicate, known, out of scope).
- **Target:** Increase acceptance rate over baseline; contest-specific (e.g. Code4rena has historical acceptance rates per severity).
- **Measurement:** When possible, use real contest results; otherwise internal panel that mimics contest rules.

### 5.5 Additional operational metrics

- **Time to first verified finding:** From audit start to first finding that passes all gates (including PoC). Lower is better for throughput.
- **Hypothesis exhaustion rate:** % of generated hypotheses that reach a terminal state (disproven, PoC passed, or abandoned with reason). Higher is better for coverage.
- **Gate rejection rate per gate:** How often each gate (tool evidence, Judge, disproof, economic, PoC) rejects a finding. Informs where to improve (e.g. if Judge rejects almost everything, relax or improve attack path quality).

---

## 6) Implementation Phases

Break the work into small, safe steps that can be implemented iteratively without a big-bang rewrite.

### Phase 1: Data model and gates (no new agents)

- Extend `Finding` (or equivalent) with **gate state** per gate (tool_evidence, pattern_fp, judge, disproof, economic, poc, invariant).
- Implement **multi-gate pipeline** as a sequence of stages; each stage sets passed/failed/dropped on the finding; report only findings that passed all applicable gates.
- Add **ProofOfExploit** artifact type: test path + impact assertion text; link Finding to ProofOfExploit when PoC is generated.
- **Success:** Pipeline runs; findings have gate states; report filters by "all gates passed." No behavior change yet if gates are permissive.

### Phase 2: Finding-specific PoC and impact assertion

- Change `generate_fork_test` (or equivalent) to accept **Finding** (or a structured view: contract, function_name, location, call_trace, state_variables) and generate test code that targets that finding (not generic oracle/reentrancy stub).
- Require PoC to include an **impact assertion** (e.g. balance change, invariant check); parse or pass assertion from Finding/Judge; run and check assertion in analyze_test_output.
- Pipeline: only set fork_verified when PoC run passes **and** impact assertion holds.
- **Success:** New or refined findings get PoCs that are tied to the finding; verified = PoC passed with assertion.

### Phase 3: Adversarial and invariant wiring

- Add **disproof agent** (prompt: try to invalidate this finding; output: disproven / not_disproven + reason). Wire as a pipeline stage after Judge; findings that are "disproven" are dropped or sent to manual review.
- Introduce **invariant researcher** as a role: agent or tool that produces invariant specs and runs Echidna/Certora; output "invariant I holds/fails." Pipeline: set invariant_broken only when a stated invariant fails for this finding.
- Optionally wire existing skeptic_alpha/beta/gamma into pipeline as a stage before exploit.
- **Success:** Every reported finding has survived disproof attempt; invariant claims are backed by runs.

### Phase 4: Attacker model and economic gate

- Define **attacker capability spec** (entrypoints, resources, constraints); recon or a dedicated step produces it per target.
- Add **economic viability** stage: consumes attack_path + attacker model + protocol context; outputs viable / not_viable / needs_manual_review. Pipeline uses this to downgrade or drop findings.
- Judge and exploit engineer prompts: only produce paths consistent with attacker model.
- **Success:** Report only includes attacks that fit the attacker model; economic gate is visible in gate state.

### Phase 5: Hypothesis-driven discovery

- Introduce **hypothesis** as first-class object (text, status: pending/supported/disproven/poc_passed).
- Hypothesis generator: from recon + invariants, produce initial hypothesis list. Coordinator assigns tools to test hypotheses; tool outputs attach as evidence to hypotheses.
- Findings are created only from hypotheses that have supporting evidence; report lists hypothesis + evidence + PoC, not raw tool output.
- PivotEngine (or equivalent) drives hypothesis refinement (e.g. reentrancy → cross-function reentrancy) when a hypothesis is disproven or PoC fails.
- **Success:** Audit runs are hypothesis-led; "no finding" is interpretable as "hypotheses exhausted or disproven."

### Phase 6: Research team roles and metrics

- Implement or refactor agents into **recon analyst**, **invariant researcher**, **attacker modeler**, **exploit engineer**, **disproof agent** with clear handoffs and prompts.
- Add **metrics collection**: per run, record exploit reproducibility, gate rejection counts, hypothesis terminal rate; optionally signal-to-noise and duplicate rate when labels or contest results exist.
- Dashboard or log that surfaces these metrics for each run.
- **Success:** Pipeline is a research team; metrics are available to tune and compare runs.

---

## Summary

This plan upgrades **methodology** first: (1) reasoning is deepened with adversarial loops, proof-of-exploit, economic and invariant reasoning, and attacker modeling; (2) a multi-gate verification pipeline ensures no finding is reported without surviving independent validations; (3) discovery moves from pattern-matching to hypothesis testing; (4) agents are restructured into a research team with recon, invariant research, attacker modeling, exploit engineering, and disproof; (5) success is measured by reproducibility, signal-to-noise, dedupe, and acceptance likelihood; (6) implementation proceeds in six phases from data model and gates through hypothesis-driven discovery and role separation, without a single big-bang change.

All of the above is aligned with the gaps and principles in [.cursor/architecture_review.md](.cursor/architecture_review.md) and is aimed at making the system suitable for competitive audit contests where accuracy and reproducibility directly determine placement and payouts.
