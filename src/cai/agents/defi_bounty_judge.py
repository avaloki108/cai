"""
DeFi Bounty Judge Agent – Exploitability Gatekeeper

Evaluates candidate findings from Hunter agents. Does NOT do discovery;
only filters: "Does this exploit work now, in current code? Show me the
exact call sequence. If mitigated, kill it."

Used in the Judge Gate pipeline: Hunter → candidates.json → Judge →
verdicts.json → only EXPLOITABLE – BOUNTY ELIGIBLE go to PoC Builder.
"""

import os
from typing import List

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.util import load_prompt_template, create_system_prompt_renderer
from openai import AsyncOpenAI

from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.exec_code import execute_code

load_dotenv()

# --- Verdict schema (contract between Judge and PoC / reporting) ---

VERDICT_EXPLOITABLE = "EXPLOITABLE – BOUNTY ELIGIBLE"
VERDICT_MITIGATED = "NOT EXPLOITABLE – ALREADY MITIGATED"
VERDICT_THEORETICAL = "THEORETICAL / DESIGN RISK ONLY"
VERDICT_INVALID = "INVALID – NO REAL ATTACK PATH"


class VerdictItem(BaseModel):
    """Single verdict for one candidate finding."""

    title: str = Field(description="Short title of the candidate (from Hunter)")
    verdict: str = Field(
        description="One of: EXPLOITABLE – BOUNTY ELIGIBLE | NOT EXPLOITABLE – ALREADY MITIGATED | THEORETICAL / DESIGN RISK ONLY | INVALID – NO REAL ATTACK PATH"
    )
    attack_path: List[str] = Field(
        default_factory=list,
        description="Numbered steps with exact entrypoints (contract.function())",
    )
    preconditions: List[str] = Field(
        default_factory=list,
        description="Explicit, minimal, in-scope state preconditions",
    )
    impact: str = Field(
        default="",
        description="Specific, measurable impact (e.g. drain X ETH from pool Y)",
    )
    reason: str = Field(
        default="",
        description="One-line justification for the verdict",
    )


class VerdictList(BaseModel):
    """Output of the Judge: one verdict per candidate."""

    verdicts: List[VerdictItem] = Field(
        default_factory=list,
        description="Verdict for each candidate; only EXPLOITABLE – BOUNTY ELIGIBLE should be promoted to PoC",
    )


# --- Judge agent ---

judge_system_prompt = load_prompt_template("prompts/system_defi_bounty_judge.md")

defi_bounty_judge_agent = Agent(
    name="DeFi Bounty Judge",
    instructions=create_system_prompt_renderer(judge_system_prompt),
    description=(
        "Exploitability gatekeeper. Evaluates candidate findings from Hunters. "
        "Outputs verdicts: only EXPLOITABLE – BOUNTY ELIGIBLE get promoted to PoC. "
        "Requires concrete call sequence with named functions and state preconditions."
    ),
    tools=[generic_linux_command, execute_code],
    output_type=VerdictList,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_DEFI_BOUNTY_JUDGE_MODEL", os.getenv("CAI_MODEL", "alias1")),
        openai_client=AsyncOpenAI(api_key=os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY"))),
    ),
)
