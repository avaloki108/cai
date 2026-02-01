"""
CAI Skills System - Claude Code/OpenAI Codex-style skills for CAI.

This module provides a skill discovery and management system that allows
CAI agents to use specialized skills defined in SKILL.md files.

Skills are discovered from:
1. User skills directory (~/.cai/skills/)
2. Project skills directory (<project>/.cai/skills/)
3. CAI built-in skills (src/cai/skills/builtin/)

Usage:
    from cai.skills import get_skill_registry, load_skills_for_agent

    # Get all available skills
    registry = get_skill_registry()
    skills = registry.list_skills()

    # Load skills for an agent
    skill_instructions = load_skills_for_agent(agent_name)
"""

from cai.skills.registry import (
    SkillRegistry,
    get_skill_registry,
    Skill,
)
from cai.skills.discovery import (
    discover_skills,
    load_skill,
    load_skills_for_agent,
)

__all__ = [
    "SkillRegistry",
    "get_skill_registry",
    "Skill",
    "discover_skills",
    "load_skill",
    "load_skills_for_agent",
]
