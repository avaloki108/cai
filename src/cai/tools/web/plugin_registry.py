from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from cai.sdk.agents import function_tool


PluginCallable = Callable[..., str]


@dataclass
class ExploitPlugin:
    name: str
    category: str
    execute: PluginCallable
    description: str


class ExploitPluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, ExploitPlugin] = {}

    def register(self, plugin: ExploitPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ExploitPlugin:
        if name not in self._plugins:
            raise KeyError(f"Plugin not found: {name}")
        return self._plugins[name]

    def list(self) -> List[ExploitPlugin]:
        return list(self._plugins.values())


REGISTRY = ExploitPluginRegistry()


@function_tool(strict_mode=False)
def list_exploit_plugins() -> str:
    return "\n".join(
        [
            f"{plugin.name} ({plugin.category}) - {plugin.description}"
            for plugin in REGISTRY.list()
        ]
    )
