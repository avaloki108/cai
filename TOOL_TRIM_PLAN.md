# CAI Tool Audit — Web3 Bug Bounty Agent
## Token Optimization Plan

**Problem:** 130 tools = ~96K tokens in system prompt. Leaves ~0 room for target code.
**Goal:** Slash to ~20 essential tools = ~18K tokens. Free up ~78K for actual analysis.

---

## KEEP (19 tools) — The Hunter's Core

| Tool | Why |
|------|-----|
| `generic_linux_command` | Shell access — run anything. Non-negotiable. |
| `execute_code` | Run Python scripts for PoCs, math verification |
| `cat_file` | Read target source code |
| `less_file` | Paginated reading for large files |
| `read_file_lines` | Targeted line reading |
| `eza_list` | Directory listing |
| `change_directory` | Navigate to target repo |
| `pwd_command` | Know where you are |
| `slither_analyze` | Core static analysis. The workhorse. |
| `slither_detectors_list` | Know what detectors are available |
| `mythril_analyze` | Symbolic execution. Complementary to slither. |
| `echidna_fuzz` (MCP) | Property-based fuzzing. Proven bug finder. |
| `medusa_fuzz` | Corpus-based fuzzing. Echidna alternative. |
| `scribble_run` | Instrument code for fuzzing |
| `wasp_quick` | Fast WASM security scan |
| `detect_web3_repo_context` | Auto-detect framework, proxies, architecture |
| `discover_proxy_patterns` | Find proxy/implementation splits |
| `validate_finding` | Check if a finding is real vs false positive |
| `list_dir` (MCP) | Browse project structure |

**Estimated tokens:** ~14K

---

## TRIM (17 tools) — Phase 2 Removal Candidates

| Tool | Why Keep (For Now) | Why Cut Later |
|------|-------------------|---------------|
| `slither_check_upgradeability` | Useful for proxy audits | Rarely needed, can use generic_linux_command + slither |
| `slither_printers_list` | Sometimes useful for deeper analysis | Niche |
| `slitheryn_analyze` | AI-powered slither wrapper | Overlaps slither_analyze; slower |
| `slitheryn_triage` | Auto-prioritize findings | Model can do this itself |
| `mythril_concolic` | Deep symbolic execution | Timeout-prone, mythril_analyze covers basics |
| `securify_analyze` | Formal verification alternative | Experimental, slow |
| `securify_critical_only` | Filtered formal checks | Experimental |
| `echidna_coverage` (MCP) | Coverage analysis | Secondary to echidna_fuzz |
| `fuzz_utils_run` | Fuzzing utilities | Overlaps echidna/medusa |
| `clorgetizer_analyze` | Gas optimizer + security side effects | Niche but has found gas-related bugs |
| `web3_rag_query` | Semantic code search | Useful if Qdrant is populated |
| `web3_kb_query` | Knowledge base for known exploits | Reference lookup |
| `web3_memory_add` | Cross-session memory | Useful for multi-day audits |
| `analyze_replay_protection` | Replay attack analysis | Good for bridge/permit audits |
| `analyze_signature_verification` | Signature validation checks | Good for meta-tx/permit audits |
| `check_known_bridge_exploits` | Bridge exploit pattern matching | Good for bridge targets |
| `wasp_audit` | Full WASP scan (slower but thorough) | Keep wasp_quick for speed |

**Estimated tokens:** ~14K (cut these later for another ~14K savings)

---

## CUT (94 tools) — Dead Weight

### Oyente (7 tools) — ABANDONED 2018
| Tool | Reason |
|------|--------|
| `oyente_analyze` | Last updated 2018, supports Solidity <0.5. Dead project. |
| `oyente_analyze_remote` | Same — dead wrapper |
| `oyente_check_vulnerability` | Dead |
| `oyente_generate_tests` | Dead |
| `oyente_with_state` | Dead |
| `oyente_print_paths` | Dead |
| `oyente_compare_contracts` | Dead |

### Securify (5 tools) — EXPERIMENTAL
| Tool | Reason |
|------|--------|
| `securify_from_blockchain` | Academic experiment, not practical |
| `securify_list_patterns` | Meta-tool, not analysis |
| `securify_compliance_check` | Compliance != vulnerability finding |
| `securify_with_interpreter` | Experimental |
| `securify_visualize_ast` | Visualization, not security analysis |

### Certora (7 tools) — REQUIRES PAID LICENSE
| Tool | Reason |
|------|--------|
| `certora_verify` | Prover requires $500+/mo license + CVL spec files |
| `certora_foundry` | Same — needs paid license |
| `certora_project_sanity` | Same |
| `certora_compilation_only` | Same |
| `certora_with_linking` | Same |
| `certora_check_invariants` | Same |
| `certora_run_tests` | Same |

### Slitheryn (6 tools) — REDUNDANT
| Tool | Reason |
|------|--------|
| `slitheryn_ai_analyze` | Overlaps slither_analyze + LLM reasoning |
| `slitheryn_print` | Printer, not detector |
| `slitheryn_list_detectors` | Redundant with slither_detectors_list |
| `slitheryn_list_printers` | Printers are low-value |
| `slitheryn_from_etherscan` | Can do this with generic_linux_command + slither |
| `slitheryn_foundry` | Can do this with generic_linux_command + slither |
| `slitheryn_hardhat` | Can do this with generic_linux_command + slither |

### Gambit (4 tools) — NICHE MUTATION TESTING
| Tool | Reason |
|------|--------|
| `gambit_mutate` | Mutation testing — academic, not practical for bounties |
| `gambit_summary` | Same |
| `gambit_run_tests` | Same |
| `gambit_analyze_survivors` | Same |

### Auditor Framework (4 tools) — UNNECESSARY ABSTRACTION
| Tool | Reason |
|------|--------|
| `auditor_run_audit` | Meta-wrapper around slither/mythril. Just use them directly. |
| `auditor_check_compliance` | Compliance != vulnerability finding |
| `auditor_generate_report` | LLM can generate reports without a tool for it |
| `auditor_scan_dependencies` | `npm audit` in a wrapper. Use generic_linux_command. |

### WASP Excess (8 tools) — ONE FRAMEWORK, 14 TOOLS
| Tool | Reason |
|------|--------|
| `wasp_ai_analyze` | LLM reasoning tool — model does this natively |
| `wasp_gen_invariants` | LLM generates invariants — just prompt the model |
| `wasp_gen_spec` | LLM generates specs — just prompt the model |
| `wasp_categories` | Meta-information |
| `wasp_tools` | Tool listing |
| `wasp_status` | Status check |
| `wasp_pattern_scan` | Overlaps wasp_quick |
| `wasp_review` | Overlaps wasp_quick |
| `wasp_learning_stats` | Machine learning stats — not useful for audit |
| `wasp_watch` | File watcher — not useful for audit |
| `wasp_dashboard` | Dashboard — not useful in CLI |
| `wasp_init` | Init — one-time setup |

### Planning/Graph/Scoring (13 tools) — LLM REASONING BLOAT
These tools make the model "think about what to do" by calling tools, burning tokens on tool-call overhead instead of actual analysis. The system prompt already handles planning. A good prompt > 13 tools.

| Tool | Reason |
|------|--------|
| `plan_web3_audit` | System prompt should cover methodology |
| `build_attack_graph` | Model should reason about this, not call a tool |
| `find_exploit_paths` | Same — LLM reasoning masquerading as a tool |
| `score_path_payoff` | Same — economic reasoning is prompt territory |
| `analyze_contract_interactions` | Model should trace interactions by reading code |
| `find_economic_invariants` | LLM reasoning tool |
| `check_invariant_violations` | LLM reasoning tool |
| `score_exploit_viability` | LLM reasoning tool |
| `rank_findings_by_exploitability` | LLM reasoning tool |
| `estimate_attacker_cost` | LLM reasoning tool |
| `aggregate_tool_results` | Post-processing wrapper |
| `correlate_findings` | Post-processing wrapper |
| `generate_strategic_digest` | Post-processing wrapper |

### Fuzzing Utilities (4 tools) — REDUNDANT
| Tool | Reason |
|------|--------|
| `generate_fuzz_seeds` | echidna/medusa handle seeds internally |
| `minimize_fuzz_corpus` | Can do with generic_linux_command |
| `analyze_fuzz_coverage` | echidna_coverage handles this (TRIM list) |
| `fuzz_utils_run` | Generic wrapper |

### Scribble Excess (5 tools) — KEEP scribble_run ONLY
| Tool | Reason |
|------|--------|
| `scribble_instrument` | scribble_run handles this |
| `scribble_arm` | scribble_disarm handles this |
| `scribble_disarm` | scribble_run can handle this |
| `scribble_mythril_verify` | Use mythril_analyze directly |
| `scribble_coverage_check` | Use echidna_coverage directly |
| `generate_scribble_annotations` | LLM can generate these without a tool |

### Memory/KB Excess (2 tools) — KEEP query/add, CUT rest
| Tool | Reason |
|------|--------|
| `web3_memory_query` | Keep in TRIM — useful for cross-session |
| `web3_kb_add` | Writing to KB during audit is premature |
| `web3_tool_status` | Checks tool availability — not useful at runtime |

### Finding Validation (2 tools) — KEEP validate, CUT rest
| Tool | Reason |
|------|--------|
| `filter_false_positives` | validate_finding covers this |
| `council_filter_findings` | Multi-model voting — interesting but token-expensive |

### Private/Internal Tools (5 tools) — SHOULD NOT BE EXPOSED
| Tool | Reason |
|------|--------|
| `_construct_role_lattice` | Private helper, no business in tool surface |
| `_detect_privilege_escalation` | Private helper |
| `_validate_domain_separator` | Private helper |
| `_analyze_nonce_replay` | Private helper |
| `_analyze_permit_flows` | Private helper |

### Bridge Analysis (2 tools) — OVERLAP
| Tool | Reason |
|------|--------|
| `render_bridge_audit_report` | Report generation — LLM does this natively |
| `analyze_message_validation` | Generic enough to be in system prompt |

### Medusa Excess (2 tools)
| Tool | Reason |
|------|--------|
| `medusa_init` | medusa_fuzz handles initialization |
| `medusa_test` | medusa_fuzz handles this |

### Mythril Excess (6 tools)
| Tool | Reason |
|------|--------|
| `mythril_safe_functions` | Niche query |
| `mythril_disassemble` | Can use generic_linux_command + disasm |
| `mythril_foundry` | Can use generic_linux_command |
| `mythril_read_storage` | Can use generic_linux_command + cast |
| `mythril_list_detectors` | Niche |
| `mythril_function_to_hash` | One-liner — use generic_linux_command |

### Misc
| Tool | Reason |
|------|--------|
| `find_file` (MCP) | Overlaps eza_list + generic_linux_command |
| `check_initialization_state` | Overlaps discover_proxy_patterns |

---

## Token Math

| Category | Tools | Est. Tokens (schemas) |
|----------|-------|----------------------|
| KEEP | 19 | ~14,000 |
| TRIM | 17 | ~14,000 |
| CUT | 94 | ~66,000 |
| **System prompt (instructions)** | - | ~2,000 |
| **Total after CUT** | **19** | **~16,000** |
| **Total current** | **130** | **~96,000** |
| **RECOVERED** | | **~80,000 tokens** |

## Impact

- Current: 96K system tokens = ~4% context left for code (at 128K window)
- After CUT: 16K system tokens = ~87% context left for code
- That's 80K+ tokens of breathing room for reading and analyzing target contracts
- A typical Solidity audit target is 10-30K tokens of source — now it fits easily

## How to Implement

The tool list is defined in the agent configuration. Check:
- `src/cai/agents/web3_bug_bounty.py` (or wherever the web3_bug_bounty_agent is defined)
- Look for the `tools=` parameter in the Agent constructor
- Remove tools from the array to trim

Or create an `agents.yml` config that lists only the KEEP tools.
