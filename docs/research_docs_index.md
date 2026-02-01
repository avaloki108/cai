# Research Docs Index (CAI Integration Map)

This index summarizes every file in `research-docs/` and maps concrete, implementable ideas into CAI code locations. Use it to translate research into engineering tasks, especially for precision gains and false-positive reduction.

---

## PDFs

### `research-docs/3727582.3728688.pdf` — Efficient LLM Adaptation for Vulnerability Detection
- **Key contributions:** classification head for detection, selective layer freezing, LoRA fine-tuning with minimal accuracy loss.
- **CAI hooks:** training pipeline under `src/cai/ml/` and any future fine-tuning tooling (e.g., `tools/web3_security/training/`).
- **Actionable ideas:**
  - Add classification-head training mode for detection tasks.
  - Implement selective layer freezing config (freeze bottom N layers).
  - Track layer-wise sensitivity to detect vulnerability-specific features.

### `research-docs/45_Towards_Hierarchical_Multi_.pdf` — HMAW for Zero-Shot Prompt Optimization
- **Key contributions:** CEO→Manager→Worker hierarchy for prompt refinement; zero-shot gains (+30.7%).
- **CAI hooks:** `src/cai/agents/patterns/hmaw.py`, `src/cai/sdk/agents/_run_impl.py`.
- **Actionable ideas:**
  - Introduce prompt-optimization stage within HMAW.
  - Generate query-specific prompts per audit target.
  - Maintain multi-level prompt artifacts (strategy → checklist → execution).

### `research-docs/autogen.pdf` — AutoGen Multi-Agent Conversation Programming
- **Key contributions:** conversable agents, conversation-centric workflows, human-in-the-loop agent types.
- **CAI hooks:** `src/cai/agents/patterns/`, `src/cai/sdk/agents/handoffs.py`.
- **Actionable ideas:**
  - Add agent “roles” that can be LLM, tool-only, or human-proxy.
  - Introduce a conversation programming layer for audits.
  - Implement explicit message routing rules with guardrails.

### `research-docs/error-multi.pdf` — ECHO Error Attribution
- **Key contributions:** hierarchical context layers + consensus voting for error attribution.
- **CAI hooks:** `src/cai/sdk/agents/tracing/`, `src/cai/tools/web3_security/triage.py`.
- **Actionable ideas:**
  - Add error attribution workflow after failed tool runs.
  - Track context at 4 levels (local → global) for debugging.
  - Use consensus voting to select likely root causes.

### `research-docs/iris-llm.pdf` — IRIS Neuro-Symbolic Static Analysis
- **Key contributions:** LLM-inferred taint specs + static analysis validation; strong FP reduction.
- **CAI hooks:** `src/cai/tools/web3_security/enhancements/iris.py`, `src/cai/tools/web3_security/triage.py`.
- **Actionable ideas:**
  - Expand LLM taint spec generation to repo-level analysis.
  - Add contextual filtering gates before reporting.
  - Introduce inter-procedural taint paths with call graphs.

### `research-docs/largetomammoth.pdf` — Large Model Evaluation in Vuln Detection
- **Key contributions:** context window size improves detection; quantization trade-offs.
- **CAI hooks:** `src/cai/sdk/agents/models/`, config in `src/cai/sdk/agents/_config.py`.
- **Actionable ideas:**
  - Add model routing based on context length and task type.
  - Evaluate quantization effects per model on CAI benchmarks.
  - Add “context budget” warnings for large repos.

### `research-docs/llm-smart-contract-vuln-detect.pdf` — GPTLens (Auditor/Critic)
- **Key contributions:** two-phase detection with high randomness generation and strict critic gating.
- **CAI hooks:** `src/cai/agents/patterns/adversarial.py`.
- **Actionable ideas:**
  - Enforce two-phase auditing as a default for Web3 runs.
  - Tighten critic scoring to require exploitability signals.
  - Add iterative refinement loop between auditor and critic.

### `research-docs/m2cvd.pdf` — Multi-Model Collaboration
- **Key contributions:** LLM+code model collaboration; refine vulnerability descriptions.
- **CAI hooks:** `src/cai/tools/web3_security/`, `src/cai/ml/`.
- **Actionable ideas:**
  - Add description refinement loop that aligns LLM output with code models.
  - Create synthetic training data from code fragments + refined descriptions.
  - Support multi-model ensembles for specialized patterns.

### `research-docs/NeurIPS-2024-swe-agent-agent-computer-interfaces-enable-automated-software-engineering-Paper-Conference.pdf` — SWE-agent ACI
- **Key contributions:** LM-friendly tool commands, concise feedback, guardrails.
- **CAI hooks:** `src/cai/tools/common.py`, `src/cai/repl/commands/`.
- **Actionable ideas:**
  - Implement LM-friendly tool wrappers with compact outputs.
  - Add guardrails to prevent invalid command execution.
  - Provide deterministic command feedback formats.

### `research-docs/react.pdf` — ReAct
- **Key contributions:** interleaved reasoning+acting reduces hallucinations.
- **CAI hooks:** `src/cai/sdk/agents/_run_impl.py`, prompt templates in `src/cai/prompts/`.
- **Actionable ideas:**
  - Insert explicit reasoning steps before tool calls.
  - Log reasoning traces alongside tool outputs.
  - Add “reasoning checkpoints” for long audits.

### `research-docs/reflexion.pdf` — Reflexion
- **Key contributions:** verbal RL + episodic memory for iterative improvements.
- **CAI hooks:** `src/cai/agents/memory.py`, `src/cai/sdk/agents/tracing/`.
- **Actionable ideas:**
  - Store failure summaries for future runs.
  - Implement retry policies driven by past failures.
  - Add reflection-based prompts after failures.

### `research-docs/TSE25_LLM-SmartAudit.pdf` and `TSE25_LLM-SmartAudit (1).pdf`
- **Key contributions:** buffer-of-thought, targeted vs broad analysis, high accuracy with multi-agent collaboration.
- **CAI hooks:** `src/cai/agents/patterns/`, `src/cai/tools/web3_security/audit_autonomous.py`.
- **Actionable ideas:**
  - Add “buffer-of-thought” memory store per audit session.
  - Implement dual modes: targeted analysis vs broad scan.
  - Use cost-aware agent orchestration per contract.

### `research-docs/usenixsecurity24-fang.pdf` — LLM Limits on Obfuscation
- **Key contributions:** LLM performance degrades on obfuscated code.
- **CAI hooks:** `src/cai/tools/web3_security/triage.py`, `src/cai/tools/web3_security/repo_context.py`.
- **Actionable ideas:**
  - Add obfuscation detection pre-check.
  - Normalize/minify source before LLM analysis.
  - Fallback to static tools when obfuscation detected.

### `research-docs/vuldetectbench.pdf` — VulDetectBench
- **Key contributions:** multi-task evaluation; models struggle on root-cause localization.
- **CAI hooks:** `benchmarks/`, `src/cai/tools/web3_security/validate_findings.py`.
- **Actionable ideas:**
  - Create a 5-task evaluation harness (detect, classify, locate root cause, identify objects, locate trigger).
  - Track metrics separately for each task category.
  - Build a “golden” Solidity suite for regression.

---

## Markdown Research Notes

### `research-docs/page-2026-01-22-21-09-51.md` — Pre-Act Planning
- **Key ideas:** plan-first multi-step reasoning before action; turn-level vs E2E metrics.
- **CAI hooks:** `src/cai/sdk/agents/_run_impl.py`, `src/cai/agents/patterns/`.

### `research-docs/page-2026-01-22-21-11-42.md` — Mythril Wrapper
- **Key ideas:** standardize tool interfaces; enforce timeouts and output validation.
- **CAI hooks:** `src/cai/tools/web3_security/mythril.py`, `src/cai/tools/common.py`.

### `research-docs/page-2026-01-22-21-13-32.md` — LLM Security Review
- **Key ideas:** two-phase detection, FP mitigation, LLM + tool validation.
- **CAI hooks:** `src/cai/agents/patterns/adversarial.py`, `src/cai/tools/web3_security/triage.py`.

### `research-docs/page-2026-01-22-21-15-18.md` — LLMBugScanner
- **Key ideas:** ensemble voting, permutation tie-breaking, self-consistency.
- **CAI hooks:** `src/cai/agents/patterns/ensemble.py`.

### `research-docs/README-smartbugs-vuln-db.md` — SmartBugs Curated
- **Key ideas:** DASP taxonomy for consistent vuln labeling.
- **CAI hooks:** `src/cai/tools/web3_security/triage.py`, output schema.

### `research-docs/chatgpt-instructions.md`
- **Key ideas:** dependency checks; minor relevance.

---

## Cross-cutting themes → CAI action points

- **False-positive reduction**: enforce two-phase detection + evidence gates + tool validation.\n- **Neuro-symbolic verification**: combine LLM hypotheses with symbolic reachability constraints.\n- **Multi-agent orchestration**: HMAW/SmartAudit for structured collaboration; consensus voting.\n- **Tool UX**: LM-friendly tools with compact, deterministic outputs and strict timeouts.\n- **Evaluation**: adopt multi-task benchmarks (VulDetectBench) with root-cause localization scoring.\n- **Reliability**: file locking, bounded caches, explicit error logging.\n\n---\n\n## Where to integrate next\n\n- **Patterns:** `src/cai/agents/patterns/` (adversarial, ensemble, hmaw, composite)\n- **Web3 pipeline:** `src/cai/tools/web3_security/` (triage, validation, orchestrator)\n- **Runtime:** `src/cai/sdk/agents/_run_impl.py` (planning, tool execution, logging)\n- **UX:** `src/cai/cli.py`, `src/cai/repl/` (setup, diagnostics)\n- **Benchmarks:** `benchmarks/` (add VulDetectBench-style harness)\n*** End Patch"}```
