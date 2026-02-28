### CAI Framework — Architecture, Build, Testing, Quality, and Security Guidelines

This document is the canonical, engineering‑facing guide for working on the CAI Framework. It consolidates architecture, build and release processes, testing policy, code quality standards, and security practices. All references below point to files that exist in this repository.

---

#### 1) Architecture Overview

- High‑level components (selected key paths)
  - CLI and UX
    - `src/cai/cli.py` (entrypoint, exposed as `cai` via `[project.scripts]` in `pyproject.toml` lines 239‑244)
    - `src/cai/repl/…` (interactive UX and commands)
  - Agent SDK (core runtime)
    - `src/cai/sdk/agents/agent.py` — base `Agent` abstraction (classes at lines 56‑235)
    - `src/cai/sdk/agents/run.py` — `Runner` orchestrates turns, tools, handoffs, guardrails (classes at lines 86‑1216)
    - `src/cai/sdk/agents/exceptions.py` — domain exceptions: `MaxTurnsExceeded`, `ModelBehaviorError`, `UserError`, guardrail tripwires, `PriceLimitExceeded`
    - `src/cai/sdk/agents/logger.py` — logger namespace `openai.agents`
  - Agents and factories
    - `src/cai/agents/*.py` — concrete agent definitions (one agent per file)
    - `src/cai/agents/factory.py` — dynamic discovery and factory creation. Reads env: `CAI_GRIT_PATH` (lines 35‑44), `CAI_MODEL` defaulting to `alias1` (lines 230‑233), `OPENAI_API_KEY` (line 234), `CAI_PARALLEL` (lines 247‑250), `CAI_SKILLS` (lines 171‑173)
  - Tools, patterns, prompts, RAG, MCP, TUI
    - `src/cai/tools/` — executable capabilities used by agents
    - `src/cai/agents/patterns/…` — coordination patterns and templates (see also `docs/multi_agent.md`)
    - `src/cai/prompts/` — prompt assets
    - `src/cai/rag/`, `src/cai/ml/` — retrieval and ML helpers
    - `src/cai/repl/` — TUI & command plumbing
    - `src/cai/mcp/` — MCP integration (see `docs/mcp.md`)
  - Documentation and tests
    - `docs/…` (MkDocs site; architecture: `docs/cai_architecture.md`, env vars: `docs/environment_variables.md`)
    - `tests/…` structured by concern (agents, core, cli, voice, tracing, mcp, tools, others)

- Module boundaries
  - `sdk/agents/*` contains the runtime engine (models, runner, IO schema, guardrails, tracing hooks). No application‑specific behavior should leak here.
  - `agents/*` defines compositions (agent instances, patterns, factories) and binds models, skills, and MCP tools.
  - `tools/*` defines concrete actions callable by agents.
  - `cli.py` + `repl/*` provide the human interface layer over the SDK.

- Data flow (simplified)
  1. CLI or API submits input → `Runner.run(...)` (`src/cai/sdk/agents/run.py`)
  2. Runner computes system prompt via `Agent.get_system_prompt(...)`, resolves `RunConfig`, output schema, tools, and handoffs
  3. Model call executed (OpenAI Chat Completions via `OpenAIChatCompletionsModel`) → responses parsed
  4. Tool calls executed if returned → results fed back into subsequent interactions
  5. Guardrails validate inputs/outputs → exceptions raised on tripwires
  6. Final `RunResult` returned; optional handoffs or parallelization applied

- Dependency graph (high‑level)
  - `cli` → `repl` → `sdk/agents` (Runner, Agent) → `models` → external LLM APIs
  - `agents/*` → `sdk/agents` + `tools` + `mcp` + prompts/skills
  - `tools/*` may call OS, network, or third‑party libs (paramiko, dnspython, etc.)
  - `docs/*` and `tests/*` depend on the public surface of `sdk/agents` and agent definitions

- External services and libraries
  - LLMs via `openai` (Chat Completions), optionally via `litellm[proxy]` (see `pyproject.toml` deps lines 16, 27)
  - Site docs built with `mkdocs` + `mkdocs-material`
  - Optional tooling: `paramiko` (SSH), `dnspython`, `networkx`, `flask`, `PyPDF2` (see `pyproject.toml` lines 30‑37)

References
- Architecture doc: `docs/cai_architecture.md`
- Workflow/dataflow: `docs/workflow-dataflow.md`
- Environment variables: `docs/environment_variables.md`

---

#### 2) Build System and Environments

- Toolchain
  - Python ≥ 3.9 (`pyproject.toml` line 6). CI should test 3.9, 3.10, 3.11, 3.12.
  - Dependency manager: `uv`; build backend: `hatchling` (`pyproject.toml` lines 90‑92)

- Local development
  - Install `uv`
  - Bootstrap: `make sync` (Makefile lines 1‑4) → equivalent to `uv sync --all-extras --all-packages --group dev`
  - Format & lint: `make format` then `make lint`
  - Type check: `make mypy`
  - Run tests: `make tests`
  - Build docs locally: `make build-docs` or `make serve-docs`

- Environment variables (minimum useful set)
  - `OPENAI_API_KEY` — required for real model calls (factory uses it, `src/cai/agents/factory.py:234`)
  - `CAI_MODEL` — global default model (defaults to `alias1`, `src/cai/agents/factory.py:230‑233`)
  - `CAI_GRIT_PATH` — extra instructions path, default `docs/grit.md` (`src/cai/agents/factory.py:35`)
  - See complete reference in `docs/environment_variables.md` (e.g., `CAI_GUARDRAILS`, `CAI_PARALLEL`, `CAI_STATE`, `CAI_MEMORY`, etc.)

- Production build & release
  - Packaging: `hatchling` (wheel+sdist include `src/cai` and selected `tools`; see `[tool.hatch.build.*]` in `pyproject.toml` lines 94‑176, 120‑151, 152‑176)
  - Manual release helper: `release_to_pypi.sh` (builds with `python3 -m build`, runs `twine check`, prints upload instructions)
  - Suggested production steps:
    1) Bump `project.version` in `pyproject.toml`
    2) Update `CHANGES.md`
    3) `./release_to_pypi.sh` (or `uv build` + `twine upload`)
    4) Tag the release in VCS: `git tag vX.Y.Z && git push --tags`

- Versioning strategy
  - Semantic Versioning (SemVer) via `project.version` (`pyproject.toml` line 3, e.g., `0.5.10`).
  - Patch: bug fixes; Minor: backward‑compatible features; Major: breaking changes with documented migrations.

---

#### 3) Testing Guidelines

- How to run
  - All tests: `make tests` → `uv run pytest` (Makefile lines 18‑21)
  - Coverage: `make coverage` (XML + terminal; fail under 95% lines, Makefile line 27; coverage config at `[tool.coverage.*]` in `pyproject.toml` lines 210‑223)
  - Python 3.9 sweep: `make old_version_tests` (Makefile lines 37‑40)

- Structure and scope
  - `tests/core/*` — model adapters, run loop, response processing
  - `tests/agents/*` — agent behavior, hooks, guardrails, max turns, streaming
  - `tests/cli/*`, `tests/mcp/*`, `tests/tracing/*`, `tests/voice/*`, `tests/tools/*`, `tests/others/*`
  - Snapshot tests: see `tests/README.md`; fix/create via `make snapshots-fix` / `make snapshots-create`

- Pytest configuration
  - `pyproject.toml [tool.pytest.ini_options]` (lines 224‑235)
    - `asyncio_mode=auto`, `testpaths=tests`
    - Marker: `allow_call_model_methods` for selectively allowing real model calls
    - Warn filter for known awaited‑coroutine pattern

- Coverage policy
  - Sources measured: `tests`, `src/cai/sdk/agents` (`[tool.coverage.run]` lines 210‑212)
  - Exclusions include `logger.debug`, abstract methods, and typing blocks (lines 216‑222)
  - Target: ≥95% lines (Makefile)

- Unit vs. integration strategy
  - Default to unit tests with fakes/mocks (e.g., `tests/fake_model.py`) for deterministic, fast feedback.
  - Integration tests are allowed behind markers or environment gates; never hard‑require external APIs or network unless explicitly marked.
  - For CLI flows, prefer black‑box tests invoking `cai` entrypoints with temp env and fixtures.

- Missing/Recommended additions
  - End‑to‑end test for an agent handoff path using only fake models/tools.
  - Negative tests for guardrail tripwires (input and output) with precise assertions on exceptions from `exceptions.py`.
  - Regression suite that loads `agents.yml.example` and validates factory discovery and cloning.
  - Golden tests for `Runner` state transitions (turn boundaries, max‑turn handling).
  - Smoke test for docs build (`mkdocs build`) in CI.

- Suggested CI outline (see `ci/test/.test.yml`, `ci/benchmarks/.benchmarks.yml`)
  - Matrix: Python {3.9, 3.10, 3.11, 3.12}
  - Steps: checkout → setup `uv` → `make sync` (cache `.venv`/uv) → `make format` (no changes), `make lint`, `make mypy` → `make tests` → `make coverage` (upload artifact)
  - Optional jobs: docs build, benchmark run (nightly), web3/tooling integration behind flags

---

#### 4) Code Quality Standards

- Linting and formatting (`pyproject.toml`)
  - `ruff` pinned in dev deps (line 63), target‑version `py39` (line 180), line‑length 100 (line 179)
  - Lint selects: `E,W,F,I,B,C4,UP` (lines 183‑191) with `isort` settings (line 192)
  - pydocstyle convention `google` (lines 194‑196); examples are allowed to be long (`examples/**/*.py` ignore E501 at line 198)
  - Commands: `make format` (format + autofix), `make lint`

- Type safety (`tool.mypy`)
  - `strict = true` with relaxed toggles for gradual typing (`disallow_untyped_* = false`, lines 201‑205)
  - Command: `make mypy`
  - Strategy: new modules should aim for typed public APIs; prefer `TypedDict`, `Protocol`, and generics where applicable (see usage across `sdk/agents/*`).

- Error handling conventions
  - Raise domain exceptions from `src/cai/sdk/agents/exceptions.py` for runner/agent/tool flow errors.
  - Guardrail violations must raise `InputGuardrailTripwireTriggered` / `OutputGuardrailTripwireTriggered`.
  - Use `UserError` for misconfiguration or invalid CLI inputs; avoid bare `Exception`.
  - Log context with `logger = logging.getLogger("openai.agents")`; use `logger.debug` for non‑critical paths (note: debug lines are excluded from coverage reports by config).

- Logging standards
  - No `print()` in library code. Use the project logger and structured messages.
  - CLI/repl may print for UX, but route diagnostic detail through the logger.
  - Avoid logging secrets or PII. Prefer stable keys in messages for grepability.

---

#### 5) Security Review Notes

- Input validation and guardrails
  - Multi‑layer guardrails are part of the runtime (see `docs/guardrails.md`, `docs/cai_architecture.md`). Enable via `CAI_GUARDRAILS=true` (see `docs/environment_variables.md`).
  - Validate tool inputs rigorously; reject shell‑dangerous patterns in output guardrails.
  - Ensure Base64/Base32 decoding checks remain enabled (documented in `docs/cai_architecture.md`).

- Dependency risk
  - Dependencies are loosely pinned (ranges in `pyproject.toml:9‑37`). Use `uv.lock` for reproducibility in CI and releases.
  - Periodically run `uv pip list --outdated` and security scanners (e.g., `pip-audit`) in CI.

- Secrets handling
  - Secrets are provided via environment or `.env` (dotenv is a dependency; see `pyproject.toml` line 26). Never commit keys.
  - Minimum required: `OPENAI_API_KEY`. Optional providers documented in `docs/environment_variables.md` (Anthropic, Mistral, Ollama, Alias PRO, etc.).

- Known weak areas / hardening recommendations
  - When `CAI_GUARDRAILS=false` (default in docs), tool execution can be risky—enable for production and CI smoke.
  - Factory falls back to `alias1` model; ensure CI sets explicit `CAI_MODEL` to avoid environment variance.
  - Tools may execute OS/network actions; run inside sandboxed environments for untrusted inputs (containers, reduced privileges).
  - Add allow‑lists for external calls in sensitive tools; gate network access in tests.

---

#### 6) Quick Start (developer workflow recap)

```bash
# 1) Setup
uv --version || pip install uv
make sync

# 2) Quality gates
make format && make lint && make mypy

# 3) Tests
make tests
make coverage   # requires ≥95% coverage

# 4) Docs (optional)
make build-docs  # or make serve-docs

# 5) Release (maintainers)
# bump version in pyproject.toml, update CHANGES.md
tools: ./release_to_pypi.sh
```

See also:
- Agents and patterns: `src/cai/agents/*`, `docs/agents.md`, `docs/multi_agent.md`
- Runner and core SDK: `src/cai/sdk/agents/*`, `docs/ref/*`
- Environment variables: `docs/environment_variables.md`
- Example configs: `agents.yml`, `agents.yml.example`
