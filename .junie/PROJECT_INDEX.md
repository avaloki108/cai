# PROJECT KNOWLEDGE MAP: Web3 Bug Bounty Agent

## 1. Component Graph
The `Web3 Bug Bounty Hunter` agent is a specialized autonomous system designed for security auditing of smart contracts and decentralized protocols. It operates within the CAI (Cybersecurity AI) framework, utilizing a tiered attack surface approach (Tier 1: Logic, Tier 2: Economic, Tier 3: Infra).

### Core Architecture
- **Agent Entrypoint**: `src/cai/agents/web3_bug_bounty.py`
    - Defines the specialized system prompt (`prompts/system_web3_bug_bounty.md`).
    - Orchestrates a suite of ~100+ tools across 15+ categories.
- **SDK Runtime**: `src/cai/sdk/agents/run.py` (The `Runner` class)
    - Manages the ReAct (Reasoning and Action) loop.
    - Handles tool execution, state management, and guardrail enforcement.
- **Model Adapter**: `src/cai/sdk/agents/model/`
    - Wraps LLM providers (OpenAI, Mistral, Anthropic) to provide a consistent interface for the agent.

### Module Connectivity & Data Flow
1.  **Reconnaissance & Context**:
    - `src/cai/tools/web3_security/enhancements/repo_context.py`: Automatically detects framework (Foundry/Hardhat), Solidity versions, and protocol type (Lending, AMM, Bridge).
    - `src/cai/tools/reconnaissance/filesystem.py`: Used by the agent to explore the directory structure and read source files.
2.  **Vulnerability Detection (Sensors)**:
    - **Static Analysis**: `src/cai/tools/web3_security/slither.py`, `slitheryn.py` (AI-enhanced), `securify.py`.
    - **Symbolic Execution**: `src/cai/tools/web3_security/mythril.py`, `oyente_plus.py`.
    - **Fuzzing**: `src/cai/tools/web3_security/echidna.py`, `medusa.py`.
    - **Formal Verification**: `src/cai/tools/web3_security/certora_prover.py`.
3.  **Strategic Reasoning (Guidance Layer)**:
    - **Graph Construction**: `src/cai/tools/web3_security/enhancements/attack_graph.py` extracts attack graphs from tool findings.
    - **Scoring (G-CTR)**: `src/cai/tools/web3_security/enhancements/exploit_scorer.py` & `attack_economics.py` compute Nash equilibria and exploitability scores (Payoff vs. Effort).
    - **Orchestration**: `src/cai/tools/web3_security/enhancements/multi_tool_orchestrator.py` correlates findings and generates a **Strategic Digest**.
4.  **Specialized Analysis**:
    - `src/cai/agents/bridge_analyzer.py`: Deep-dive checks for cross-chain message validation, signature verification, and replay protection.

## 2. Capability Map
| Capability | Key Modules / Files |
| :--- | :--- |
| **Vulnerability Detection** | `slither.py`, `mythril.py`, `echidna.py`, `securify.py`, `slitheryn.py` |
| **Reasoning & Planning** | `run.py` (Runner), `multi_tool_orchestrator.py` (Digest), `repo_context.py` |
| **Exploitation Modeling** | `attack_graph.py` (Path Discovery), `exploit_scorer.py` (Viability), `mev_simulator.py` |
| **Report Generation** | `auditor_framework.py`, `bridge_analyzer.py` (Audit Report), `multi_tool_orchestrator.py` |
| **Domain Expertise** | `bridge_analyzer.py` (Bridges), `protocols/` (Lending, AMM, ERC4626) |

## 3. Blind Spots
- **Environment & Tooling**:
    - The agent assumes a correctly configured environment where `solc`, `foundry`, `slither`, and `mythril` are available in the PATH. Failure to find these binaries often leads to "tool not found" errors that the LLM may struggle to resolve.
- **Context Window Constraints**:
    - Large repositories or long tool outputs (e.g., thousands of lines of Slither JSON) can exceed the LLM's context window, leading to "forgotten" findings or truncated analysis.
- **Dynamic State Assumptions**:
    - Economic vulnerability analysis (`attack_economics.py`) often uses static snapshots or simplified models and may miss complex, state-dependent front-running or sandwiching opportunities.
- **False Positive Triage**:
    - While `validate_findings.py` exists, the agent heavily relies on the LLM's interpretation of tool output. Subtle logical flaws in complex DeFi protocols might be hallucinated or missed if the tool output is ambiguous.
- **Permissioned vs. Permissionless**:
    - Game-theoretic scoring (`G-CTR`) prioritizes permissionless exploits. It may undervalue critical bugs that require specific roles (e.g., Owner, DAO) if the agent assumes those roles are unreachable.

## 4. External Tool Integration
The CAI framework acts as a high-level wrapper and reasoning engine over industry-standard security tools:

- **Slither / Foundry**: Integrated via subprocess calls. Foundry (`forge`) is used for compilation, unit testing, and invariant verification.
- **Echidna / Medusa**: Triggered for property-based fuzzing. The agent translates high-level security properties into `echidna` test contracts.
- **Mythril**: Used for symbolic path exploration. The agent consumes Mythril's JSON findings to identify deep logic vulnerabilities.
- **G-CTR Guidance**: The agent implements the Generative Cut-the-Rope (G-CTR) method. It feeds raw tool logs into the enhancement layer, which returns a "Strategic Digest" (chess-like best lines) that the agent uses to refine its next steps.
- **LLM as the Glue**: The LLM does not perform the heavy lifting of static analysis; instead, it interprets the *results* of specialized tools, correlates them across files, and builds the exploitation narrative.

## 5. Vulnerability Detection Flow

For each class of vulnerability, the detection pipeline follows a tiered progression from raw sensors to game-theoretic triage.

### 5.1 Logic Flaws
1. **Pipeline Start**: Static analysis (Slither/Slitheryn) or Symbolic execution (Mythril).
2. **Detecting Module**: `slitheryn.py` (AI-enhanced static analysis) identifies non-standard state transitions or inconsistent access controls.
3. **Filtering/Downgrading Module**: `validation.py` (during triage) filters out findings that follow standard patterns (e.g., safe usage of `tx.origin` for auth).
4. **False Negatives**: Deeply nested branch-dependent logic where the fuzzer hits low coverage and symbolic execution times out.
5. **Missing Signals**: High-level protocol specifications or business intent (what the contract *should* do vs. what it does).

### 5.2 Economic Exploits (Price Manipulation, Oracle Attacks)
1. **Pipeline Start**: Reconnaissance (detecting oracles) -> `attack_economics.py` / `mev_simulator.py`.
2. **Detecting Module**: `exploit_scorer.py` / `attack_economics.py` computes the Nash equilibrium between attack cost and expected payoff.
3. **Filtering/Downgrading Module**: `exploit_scorer.py` downgrades if the payoff is below the cost of gas and capital (Flash Loan fees).
4. **False Negatives**: Multi-step flash-loan manipulation of thin liquidity pools where the price impact isn't captured by static price checks.
5. **Missing Signals**: Real-time liquidity depth and mempool state (currently uses static snapshots from `attack_economics.py`).

### 5.3 Cross-Contract Exploits (Reentrancy, Untrusted Calls)
1. **Pipeline Start**: Call Graphing -> `cross_contract.py` / `attack_graph.py`.
2. **Detecting Module**: `attack_graph.py` extracts call flows across heterogeneous protocol boundaries.
3. **Filtering/Downgrading Module**: `multi_tool_orchestrator.py` filters "safe" reentrancy patterns where Check-Effects-Interactions is preserved.
4. **False Negatives**: Cross-function or cross-contract reentrancy where the state change occurs in an external, unlinked contract.
5. **Missing Signals**: A unified, global state view across the entire protocol suite during the ReAct loop.

### 5.4 Replay/Signature Issues
1. **Pipeline Start**: Specialized Analysis -> `bridge_analyzer.py` or signature-specific Slither detectors.
2. **Detecting Module**: `bridge_analyzer.py` checks for EIP-712 domain separators, nonces, and chain IDs.
3. **Filtering/Downgrading Module**: `web3_bug_bounty.py` (LLM triage) downgrades theoretical malleability if it doesn't lead to a fund-drain.
4. **False Negatives**: Malleable signatures in custom ECDSA implementations or insufficient domain separators in complex cross-chain messages.
5. **Missing Signals**: Historical on-chain data for nonce usage or previously submitted signature hashes.

### 5.5 Governance Attacks
1. **Pipeline Start**: Context Discovery (`repo_context.py`) -> `exploit_scorer.py`.
2. **Detecting Module**: `exploit_scorer.py` (Governance Attacker model) identifies vulnerabilities in voting weight calculation.
3. **Filtering/Downgrading Module**: `G-CTR` logic prioritizes permissionless exploits over role-based attacks.
4. **False Negatives**: Governance takeover via flash-voting if the voting period is too short for the agent to simulate the window.
5. **Missing Signals**: Actual token distribution and voting power concentration among existing holders.

### 5.6 Upgradeability Bugs
1. **Pipeline Start**: Static Analysis (`slither_check_upgradeability`) -> `securify.py`.
2. **Detecting Module**: `slither_check_upgradeability` flags uninitialized implementations or self-destruct patterns.
3. **Filtering/Downgrading Module**: `slitheryn_triage` removes findings for standard proxy patterns (e.g., OpenZeppelin `UUPS`).
4. **False Negatives**: Storage collisions in deep inheritance trees that are missed by Slither's storage layout diffing.
5. **Missing Signals**: Complete storage layout of the *previous* implementation for accurate collision detection.

## 6. Detection Failure Modes

The agent's structural weaknesses lead to real-world exploits escaping detection in the following ways:

1. **Tool Isolation**: Static analysis tools (Slither) lack price-awareness, while economic tools (`attack_economics.py`) lack deep code insight, creating "seams" where complex, multi-stage exploits hide.
2. **Reasoning Gaps**: The LLM may fail to connect a "Medium" severity logic error in a seemingly auxiliary contract to a "Critical" economic drain in the main vault.
3. **Missing Correlation**: Failure to correlate low-level memory/storage issues (detected by Mythril) with high-level protocol invariants (checked by Echidna).
4. **Incorrect Prioritization**: `G-CTR` game-theoretic scoring over-penalizes "privileged" attacks, potentially missing critical bugs reachable by compromised or maliciously initialized roles.
5. **Economic Modeling Limits**: Static snapshots in `mev_simulator.py` cannot capture reflexive price impact or "sandwiching" dynamics that depend on the agent's own hypothetical transactions.
