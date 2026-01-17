from cai.repl.commands.parallel import ParallelConfig

# NOTE: Keep this pattern name distinct.
#
# There is a separate, primary "offsec_pattern" in `offsec.py` meant to be a
# quick-start parallel pattern using real agents. This file historically
# provided a swarm-based variant, but naming it the same caused it to override
# the primary pattern during discovery (leading to "pattern agents" with 0
# tools).
offsec_swarm_pattern = {
    "name": "offsec_swarm_pattern",
    "type": "parallel",
    "description": (
        "Bug bounty and red team swarms with different contexts for "
        "offensive security ops"
    ),
    "configs": [
        ParallelConfig("redteam_swarm_pattern"),
        ParallelConfig("bb_triage_swarm_pattern"),
    ],
    "unified_context": False,
}