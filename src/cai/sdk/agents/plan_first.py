"""Plan-first prompt helpers (Pre-Act style)."""

from __future__ import annotations

import os
from typing import Any


DEFAULT_PLAN_PROMPT = (
    "Before acting, write a short step-by-step plan and expected artifacts. "
    "Then proceed with the requested task."
)


def apply_plan_first(input_data: Any, failures_summary: str = "") -> Any:
    """Inject a plan-first directive into string inputs."""
    if not isinstance(input_data, str):
        return input_data
    plan_prompt = os.getenv("CAI_PLAN_FIRST_PROMPT", DEFAULT_PLAN_PROMPT)
    parts = [plan_prompt]
    if failures_summary:
        parts.append(failures_summary)
    parts.append("User request:\n" + input_data)
    return "\n\n".join(parts)
