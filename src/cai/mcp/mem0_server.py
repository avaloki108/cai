"""
mem0 MCP Server for CAI.

Exposes mem0 long-term memory as MCP tools so that any cai agent can
persist and retrieve memories across sessions.

Memory is keyed by user_id (default: "cai") so different users/workspaces
can maintain separate memory spaces.

Environment variables:
    MEM0_USER_ID      - Default user id for memory ops (default: "cai")
    MEM0_CONFIG_PATH  - Path to a JSON/YAML mem0 config file (optional)
    MEM0_QDRANT_URL   - Qdrant URL for vector store (optional, local in-process if unset)
    MEM0_EMBED_MODEL  - Embedding model (default: text-embedding-3-small)
    MEM0_LLM_MODEL    - LLM for memory extraction (default: gpt-4.1-nano-2025-04-14)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# mem0 configuration
# ---------------------------------------------------------------------------

DEFAULT_USER_ID = os.getenv("MEM0_USER_ID", "cai")
HISTORY_DB_PATH = str(Path.home() / ".cai" / "mem0" / "history.db")
QDRANT_PATH = str(Path.home() / ".cai" / "mem0" / "qdrant")

Path(HISTORY_DB_PATH).parent.mkdir(parents=True, exist_ok=True)

# Build a local config that needs no external services.
_DEFAULT_CONFIG: dict[str, Any] = {
    "version": "v1.1",
    "vector_store": {
        "provider": "qdrant",
        "config": {
            "collection_name": "cai_mem0",
            "path": QDRANT_PATH,
            "on_disk": True,
        },
    },
    "llm": {
        "provider": "openai",
        "config": {
            "model": os.getenv("MEM0_LLM_MODEL", "gpt-4.1-nano-2025-04-14"),
            "temperature": 0.1,
        },
    },
    "embedder": {
        "provider": "openai",
        "config": {
            "model": os.getenv("MEM0_EMBED_MODEL", "text-embedding-3-small"),
        },
    },
    "history_db_path": HISTORY_DB_PATH,
}

# Allow overriding via a JSON config file
_config_path = os.getenv("MEM0_CONFIG_PATH")
if _config_path and Path(_config_path).exists():
    try:
        with open(_config_path) as _f:
            _DEFAULT_CONFIG = json.load(_f)
        logger.info("mem0 MCP: loaded config from %s", _config_path)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("mem0 MCP: failed to load config from %s: %s", _config_path, exc)

# Lazy-initialise the memory instance to avoid slow imports at module load
_memory: Any | None = None


def _get_memory() -> Any:
    """Return (and lazily create) the global Memory instance."""
    global _memory  # pylint: disable=global-statement
    if _memory is None:
        from mem0 import Memory  # pylint: disable=import-outside-toplevel

        _memory = Memory.from_config(_DEFAULT_CONFIG)
    return _memory


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("mem0-memory")


@mcp.tool()
def add_memory(
    content: str,
    user_id: str = DEFAULT_USER_ID,
    agent_id: str | None = None,
    run_id: str | None = None,
    metadata: str | None = None,
) -> str:
    """Store a new memory.

    Args:
        content: The text to remember (free-form, e.g. a fact, observation, conversation excerpt).
        user_id: Namespace for the memory (default: "cai").
        agent_id: Optional agent identifier to further scope the memory.
        run_id: Optional run/session identifier.
        metadata: Optional JSON string with extra key/value metadata.

    Returns:
        JSON string with the created memory ids.
    """
    mem = _get_memory()
    kwargs: dict[str, Any] = {"user_id": user_id}
    if agent_id:
        kwargs["agent_id"] = agent_id
    if run_id:
        kwargs["run_id"] = run_id
    if metadata:
        try:
            kwargs["metadata"] = json.loads(metadata)
        except Exception:
            kwargs["metadata"] = {"raw": metadata}

    messages = [{"role": "user", "content": content}]
    result = mem.add(messages, **kwargs)
    return json.dumps(result, default=str)


@mcp.tool()
def search_memory(
    query: str,
    user_id: str = DEFAULT_USER_ID,
    agent_id: str | None = None,
    run_id: str | None = None,
    limit: int = 5,
) -> str:
    """Search memories by semantic similarity.

    Args:
        query: Natural-language search query.
        user_id: Namespace to search in (default: "cai").
        agent_id: Optionally restrict to a specific agent.
        run_id: Optionally restrict to a specific run.
        limit: Maximum number of results (default: 5).

    Returns:
        JSON array of matching memory objects with id, memory text, and score.
    """
    mem = _get_memory()
    kwargs: dict[str, Any] = {"user_id": user_id, "limit": limit}
    if agent_id:
        kwargs["agent_id"] = agent_id
    if run_id:
        kwargs["run_id"] = run_id

    results = mem.search(query, **kwargs)
    # results is typically {"results": [...]}
    return json.dumps(results, default=str)


@mcp.tool()
def get_all_memories(
    user_id: str = DEFAULT_USER_ID,
    agent_id: str | None = None,
    run_id: str | None = None,
    limit: int = 50,
) -> str:
    """Retrieve all memories for a user/agent/run.

    Args:
        user_id: Namespace to retrieve from (default: "cai").
        agent_id: Optionally restrict to a specific agent.
        run_id: Optionally restrict to a specific run.
        limit: Maximum number of results (default: 50).

    Returns:
        JSON array of memory objects.
    """
    mem = _get_memory()
    kwargs: dict[str, Any] = {"user_id": user_id, "limit": limit}
    if agent_id:
        kwargs["agent_id"] = agent_id
    if run_id:
        kwargs["run_id"] = run_id

    results = mem.get_all(**kwargs)
    return json.dumps(results, default=str)


@mcp.tool()
def delete_memory(memory_id: str) -> str:
    """Delete a specific memory by its id.

    Args:
        memory_id: The id of the memory to delete (obtained from search or get_all).

    Returns:
        JSON confirmation.
    """
    mem = _get_memory()
    result = mem.delete(memory_id)
    return json.dumps(result, default=str)


@mcp.tool()
def update_memory(memory_id: str, new_content: str) -> str:
    """Update the text of an existing memory.

    Args:
        memory_id: The id of the memory to update.
        new_content: The new text for the memory.

    Returns:
        JSON confirmation with the updated memory.
    """
    mem = _get_memory()
    result = mem.update(memory_id, new_content)
    return json.dumps(result, default=str)


if __name__ == "__main__":
    mcp.run(transport="stdio")
