"""
Web3 bootstrap pattern for cloned repos.

Ensures the repo builds/tests, optionally starts a local fork,
and produces repo context JSON with prioritized audit starting points.
"""

from cai.repl.commands.parallel import ParallelConfig

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
                "ROLE: Environment + Build Runner. "
                "Detect framework (Foundry/Hardhat/Truffle) and run fast install + test. "
                "If fork metadata provided, start anvil --fork-url / Hardhat forking. "
                "Do not touch live networks."
            ),
        ),
        ParallelConfig(
            "web3_bug_bounty_agent",
            prompt=(
                "ROLE: Repo Context Builder. "
                "Run detect_web3_repo_context(repo_path) and output JSON verbatim. "
                "Summarize: proxies, oracles, key invariants, critical paths. "
                "Optionally run a quick slither_analyze sanity check if builds succeed."
            ),
        ),
    ],
}
