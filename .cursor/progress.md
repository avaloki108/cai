# Improvement Plan Progress

Tracking implementation of [.cursor/improvement_plan.md](../.cursor/improvement_plan.md). Each entry records what changed, why it matters for vulnerability discovery, and how it reduces false positives or improves exploitability detection.

---

## Step 1: Data model and gates (Phase 1 — partial)

**What changed**

- Extended `Finding` in [src/cai/core/finding.py](../src/cai/core/finding.py) with:
  - `GateResult` type and `GateState` dataclass (tool_evidence, pattern_fp, judge, disproof, economic, poc, invariant).
  - `ProofOfExploit` dataclass (test_file, impact_assertion).
  - `Finding.gate_state`, `Finding.proof_of_exploit`, and `passed_all_applicable_gates()`.
- Added tests in [tests/core/test_finding.py](../tests/core/test_finding.py) for GateState, ProofOfExploit, and gate logic.

**Why it matters for vulnerability discovery**

- Findings can carry a structured verification state per gate instead of only booleans (e.g. `fork_verified`). Later phases can require “passed” at each gate before a finding is reported, aligning with the improvement plan’s multi-gate verification pipeline.
- `ProofOfExploit` links a finding to a runnable PoC and an impact assertion, which is required for “verified” status in the plan.

**How it reduces false positives / improves exploitability detection**

- No behavior change yet: gates are optional and default to “not set”; `passed_all_applicable_gates()` returns True when no gate is set (backward compatible). Once pipeline stages set gate results, report filtering by `passed_all_applicable_gates()` will exclude findings that failed or were dropped at any evaluated gate, reducing false positives. The data model enables future steps (finding-specific PoC, impact assertion, adversarial gate) without speculative detection.

---

## Step 2: Wire gate state into pipeline and report

**What changed**

- **Pipeline stages** in [src/cai/web3/pipeline.py](../src/cai/web3/pipeline.py) now set gate results on each Finding:
  - Discovery: `gate_state.tool_evidence = "passed"` for every finding (Slither or precision detector).
  - Skeptic: `gate_state.pattern_fp = "dropped"` when rejected (owner-only or no state mutation); `pattern_fp = "passed"` when the finding survives.
  - Exploit: `gate_state.poc = "failed"` on fork/test failure or unprofitable; `poc = "passed"` when fork_verified.
  - Formal: `gate_state.invariant = "passed"` when invariant_broken is True; `invariant = "failed"` otherwise.
- **Report** in `generate_report()`:
  - Added `_gate_state_to_dict()`; each finding in the report includes `gate_state`.
  - Added `verified_findings` list (findings that `passed_all_applicable_gates()`).
  - Added `summary.verified_findings_count`.
- **Tests**: Pipeline-scenario gate state tests and report structure test (gate_state, verified_findings) in [tests/core/test_finding.py](../tests/core/test_finding.py).

**Why it matters for vulnerability discovery**

- The pipeline now records why each finding survived or was filtered at each stage. Downstream logic and humans can see exactly which gate (tool_evidence, pattern_fp, poc, invariant) passed or failed. This supports auditing and future gates (judge, disproof, economic).
- `verified_findings` is the subset of findings that passed all applicable gates; it is the intended list for “high-accuracy” reporting in the improvement plan.

**How it reduces false positives / improves exploitability detection**

- Reduces false positives: findings that fail the skeptic (pattern_fp = "dropped") or the exploit stage (poc = "failed") or the formal stage (invariant = "failed") are still in the pipeline until report time, but they are excluded from `verified_findings`. Consumers can rely on `verified_findings` as the gate-filtered set. Existing `findings` (critical by `is_critical()`) are unchanged for backward compatibility.
- Improves exploitability detection: only findings that pass tool_evidence, pattern_fp, poc, and (when set) invariant are in verified_findings; this moves reporting toward “provable exploitation capability” without adding new speculative checks—gates reflect the existing pipeline’s decisions.
