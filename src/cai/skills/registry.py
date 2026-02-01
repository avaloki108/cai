"""
Skill Registry for CAI.

Manages the registration, enabling/disabling, and retrieval of skills.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from cai.sdk.agents.logger import logger


@dataclass
class Skill:
    """Represents a CAI skill."""

    name: str
    description: str
    path: Path
    content: str
    source: str  # 'user', 'project', 'builtin'
    tags: List[str] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)  # Specific agents this skill applies to
    always_apply: bool = False  # If True, always include for all agents

    def __hash__(self):
        return hash(self.path)


class SkillRegistry:
    """
    Registry for managing CAI skills.

    Tracks available skills and which ones are enabled/disabled.
    """

    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._enabled: Set[str] = set()
        self._disabled: Set[str] = set()
        self._config_path = Path.home() / ".cai" / "skills_config.json"
        self._load_config()

    def _load_config(self):
        """Load enabled/disabled skills configuration."""
        if self._config_path.exists():
            try:
                with open(self._config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self._enabled = set(config.get("enabled", []))
                    self._disabled = set(config.get("disabled", []))
            except (json.JSONDecodeError, OSError) as e:
                logger.debug("Failed to load skills config: %s", e)

    def _save_config(self):
        """Save enabled/disabled skills configuration."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "enabled": list(self._enabled),
                        "disabled": list(self._disabled),
                    },
                    f,
                    indent=2,
                )
        except OSError as e:
            logger.debug("Failed to save skills config: %s", e)

    def register(self, skill: Skill) -> None:
        """Register a skill in the registry."""
        self._skills[skill.name] = skill
        # If not explicitly disabled, enable by default
        if skill.name not in self._disabled:
            self._enabled.add(skill.name)

    def unregister(self, name: str) -> None:
        """Unregister a skill from the registry."""
        if name in self._skills:
            del self._skills[name]
            self._enabled.discard(name)
            self._disabled.discard(name)

    def get(self, name: str) -> Optional[Skill]:
        """Get a skill by name."""
        return self._skills.get(name)

    def list_skills(self) -> List[Skill]:
        """List all registered skills."""
        return list(self._skills.values())

    def list_enabled(self) -> List[Skill]:
        """List all enabled skills."""
        return [s for s in self._skills.values() if s.name in self._enabled]

    def list_disabled(self) -> List[Skill]:
        """List all disabled skills."""
        return [s for s in self._skills.values() if s.name in self._disabled]

    def enable(self, name: str) -> bool:
        """Enable a skill."""
        if name not in self._skills:
            return False
        self._enabled.add(name)
        self._disabled.discard(name)
        self._save_config()
        return True

    def disable(self, name: str) -> bool:
        """Disable a skill."""
        if name not in self._skills:
            return False
        self._disabled.add(name)
        self._enabled.discard(name)
        self._save_config()
        return True

    def is_enabled(self, name: str) -> bool:
        """Check if a skill is enabled."""
        return name in self._enabled

    def get_skills_for_agent(self, agent_name: str) -> List[Skill]:
        """
        Get all enabled skills applicable to a specific agent.

        Returns skills that:
        1. Are enabled
        2. Have always_apply=True OR
        3. Have the agent_name in their agents list OR
        4. Have an empty agents list (applies to all)
        """
        applicable = []
        agent_name_lower = agent_name.lower() if agent_name else ""

        for skill in self.list_enabled():
            if skill.always_apply:
                applicable.append(skill)
            elif not skill.agents:  # Empty list means all agents
                applicable.append(skill)
            elif agent_name_lower in [a.lower() for a in skill.agents]:
                applicable.append(skill)

        return applicable

    def clear(self) -> None:
        """Clear all registered skills."""
        self._skills.clear()
        self._enabled.clear()
        # Don't clear disabled - preserve user preferences


# Global registry instance
_REGISTRY: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    """Get the global skill registry instance."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = SkillRegistry()
    return _REGISTRY


def reset_skill_registry() -> None:
    """Reset the global skill registry (mainly for testing)."""
    global _REGISTRY
    _REGISTRY = None
