"""
Web3 bootstrap pattern for cloned repos.

- Ensures the repo builds/tests and optional local fork.
- Produces repo context JSON and prioritized audit starting points.
"""

from cai.repl.commands.parallel import ParallelConfig

# NOTE: Keep unified_context False to avoid cross-contamination between lanes.
web3_bootstrap_pattern = {
    "name": "web3_bootstrap_pattern",
    "type": "parallel",
    "description": (
        "Bootstrap cloned repo: install/build/test + optional local fork + context summary."
    ),
    "unified_context": False,
    "configs": [
        ParallelConfig(
            "one_tool_agent",
            prompt=(
                "ROLE: Environment + Build Runner.\n"
                "1) Ask user for repo path if not provided.\n"
                "2) Detect framework and run fast installs/tests:\n"
                "- Foundry: forge --version; forge test -vvv (or -vv)\n"
                "- Hardhat: node -v; npm/yarn/pnpm install; npx hardhat test\n"
                "3) If user provides fork metadata, start local fork:\n"
                "- anvil --fork-url <URL> --fork-block-number <N> (or Hardhat forking)\n"
                "Do not touch live networks. Prefer fast commands. Emit output frequently."
            ),
        ),
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Repo Context Builder.\n"
                "1) Ask user for repo path if not provided.\n"
                "2) Run detect_web3_repo_context(repo_path) and output the JSON verbatim.\n"
                "3) Summarize architecture: proxies, oracles, key invariants, critical paths.\n"
                "4) Optionally run a quick slither_analyze sanity check if builds succeed.\n"
                "Output: context JSON + prioritized audit starting points."
            ),
        ),
    ],
}
