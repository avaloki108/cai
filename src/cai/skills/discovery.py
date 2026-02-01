"""
Skill Discovery for CAI.

Discovers and loads skills from SKILL.md files in various locations.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from cai.sdk.agents.logger import logger
from cai.skills.registry import Skill, get_skill_registry


def _parse_skill_frontmatter(content: str) -> Tuple[Dict, str]:
    """
    Parse YAML frontmatter from skill content.

    Returns:
        Tuple of (metadata dict, remaining content)
    """
    if not content.startswith("---"):
        return {}, content

    lines = content.split("\n")
    end_idx = -1
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            end_idx = i
            break

    if end_idx == -1:
        return {}, content

    try:
        frontmatter = yaml.safe_load("\n".join(lines[1:end_idx]))
        remaining = "\n".join(lines[end_idx + 1 :]).strip()
        return frontmatter or {}, remaining
    except yaml.YAMLError:
        return {}, content


def load_skill(path: Path, source: str = "unknown") -> Optional[Skill]:
    """
    Load a skill from a SKILL.md file.

    Args:
        path: Path to the SKILL.md file
        source: Source identifier ('user', 'project', 'builtin')

    Returns:
        Skill object or None if loading fails
    """
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.debug("Failed to read skill file %s: %s", path, e)
        return None

    metadata, body = _parse_skill_frontmatter(content)

    # Extract skill name from metadata or directory name
    name = metadata.get("name")
    if not name:
        # Use parent directory name as skill name
        name = path.parent.name if path.name == "SKILL.md" else path.stem

    description = metadata.get("description", "")
    tags = metadata.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    agents = metadata.get("agents", [])
    if isinstance(agents, str):
        agents = [a.strip() for a in agents.split(",")]

    always_apply = metadata.get("alwaysApply", metadata.get("always_apply", False))

    return Skill(
        name=name,
        description=description,
        path=path,
        content=body,
        source=source,
        tags=tags,
        agents=agents,
        always_apply=always_apply,
    )


def _discover_in_directory(directory: Path, source: str) -> List[Skill]:
    """
    Discover skills in a directory.

    Looks for:
    - <dir>/SKILL.md
    - <dir>/<subdir>/SKILL.md (nested skills)
    """
    skills = []

    if not directory.exists():
        return skills

    # Check for SKILL.md directly in directory
    skill_file = directory / "SKILL.md"
    if skill_file.exists():
        skill = load_skill(skill_file, source)
        if skill:
            skills.append(skill)

    # Check subdirectories for SKILL.md files
    try:
        for item in directory.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                skill_file = item / "SKILL.md"
                if skill_file.exists():
                    skill = load_skill(skill_file, source)
                    if skill:
                        skills.append(skill)
    except OSError as e:
        logger.debug("Error scanning directory %s: %s", directory, e)

    return skills


def discover_skills(project_path: Optional[Path] = None) -> List[Skill]:
    """
    Discover all available skills from various locations.

    Search order (later sources can override earlier):
    1. CAI built-in skills (src/cai/skills/builtin/)
    2. Claude Code skills (~/.claude/skills/)
    3. Cursor skills (~/.cursor/skills-cursor/ and ~/.cursor-nightly/skills-cursor/)
    4. User CAI skills (~/.cai/skills/)
    5. Project skills (<project>/.cai/skills/)

    Args:
        project_path: Optional project directory to search for project skills

    Returns:
        List of discovered skills
    """
    registry = get_skill_registry()
    registry.clear()

    all_skills = []

    # 1. Built-in skills
    builtin_path = Path(__file__).parent / "builtin"
    builtin_skills = _discover_in_directory(builtin_path, "builtin")
    all_skills.extend(builtin_skills)

    # 2. Claude Code skills (~/.claude/skills/)
    claude_skills_path = Path.home() / ".claude" / "skills"
    claude_skills = _discover_in_directory(claude_skills_path, "claude")
    all_skills.extend(claude_skills)

    # 3. Cursor skills (~/.cursor/skills-cursor/)
    cursor_skills_path = Path.home() / ".cursor" / "skills-cursor"
    cursor_skills = _discover_in_directory(cursor_skills_path, "cursor")
    all_skills.extend(cursor_skills)

    # 3b. Cursor nightly skills (~/.cursor-nightly/skills-cursor/)
    cursor_nightly_path = Path.home() / ".cursor-nightly" / "skills-cursor"
    cursor_nightly_skills = _discover_in_directory(cursor_nightly_path, "cursor-nightly")
    all_skills.extend(cursor_nightly_skills)

    # 4. User CAI skills (~/.cai/skills/)
    user_skills_path = Path.home() / ".cai" / "skills"
    user_skills = _discover_in_directory(user_skills_path, "user")
    all_skills.extend(user_skills)

    # 5. Project skills
    if project_path:
        project_skills_path = project_path / ".cai" / "skills"
        project_skills = _discover_in_directory(project_skills_path, "project")
        all_skills.extend(project_skills)
    else:
        # Try current working directory
        cwd_skills_path = Path.cwd() / ".cai" / "skills"
        cwd_skills = _discover_in_directory(cwd_skills_path, "project")
        all_skills.extend(cwd_skills)

    # Also check environment variable for additional skill paths
    extra_paths = os.getenv("CAI_SKILLS_PATH", "")
    if extra_paths:
        for path_str in extra_paths.split(":"):
            extra_path = Path(path_str.strip())
            if extra_path.exists():
                extra_skills = _discover_in_directory(extra_path, "extra")
                all_skills.extend(extra_skills)

    # Register all discovered skills
    for skill in all_skills:
        registry.register(skill)

    logger.debug("Discovered %d skills", len(all_skills))
    return all_skills


def load_skills_for_agent(agent_name: Optional[str] = None) -> str:
    """
    Load and combine skill instructions for an agent.

    Args:
        agent_name: Name of the agent to load skills for

    Returns:
        Combined skill instructions as a string
    """
    # Ensure skills are discovered
    registry = get_skill_registry()
    if not registry.list_skills():
        discover_skills()

    # Get applicable skills
    skills = registry.get_skills_for_agent(agent_name or "")

    if not skills:
        return ""

    # Combine skill content
    sections = []
    for skill in skills:
        sections.append(f"<skill name=\"{skill.name}\">\n{skill.content}\n</skill>")

    if sections:
        combined = "\n\n".join(sections)
        return f"\n<skills>\n{combined}\n</skills>\n"

    return ""


def get_skill_content(skill_name: str) -> Optional[str]:
    """
    Get the full content of a specific skill.

    Args:
        skill_name: Name of the skill

    Returns:
        Skill content or None if not found
    """
    registry = get_skill_registry()
    skill = registry.get(skill_name)
    return skill.content if skill else None
