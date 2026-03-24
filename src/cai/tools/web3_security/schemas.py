from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional


class RiskLevel(str, Enum):
    SAFE = "safe"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


class ChainType(str, Enum):
    EVM = "evm"
    SOLANA = "solana"
    APTOS = "aptos"
    NEAR = "near"
    MULTI = "multi"


class ExposureSurface(str, Enum):
    AGENT = "agent"
    MCP = "mcp"
    ANY = "any"


PluginExecutor = Callable[[Dict[str, Any]], Any]


@dataclass
class Web3PluginMetadata:
    name: str
    description: str
    category: str
    risk_level: RiskLevel
    requires_aggressive: bool
    input_schema: Dict[str, Any]
    supports_fork_test: bool
    supports_formal_verification: bool
    mutates_state: bool
    chain_type: ChainType


@dataclass
class Web3Plugin:
    metadata: Web3PluginMetadata
    execute: PluginExecutor


@dataclass
class PluginRunRequest:
    plugin_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    policy_level: RiskLevel = RiskLevel.SAFE
    allow_aggressive: bool = False
    dry_run: bool = False
    timeout_sec: int = 30
    exposure_surface: ExposureSurface = ExposureSurface.AGENT


@dataclass
class PluginRunMeta:
    risk_level: str
    aggressive: bool
    duration_ms: int
    timestamp: str
    version: str = "1"


@dataclass
class PluginRunResponse:
    ok: bool
    plugin: str
    request_id: str
    input: Dict[str, Any]
    result: Optional[Dict[str, Any]]
    error: Optional[Dict[str, Any]]
    meta: PluginRunMeta

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "plugin": self.plugin,
            "request_id": self.request_id,
            "input": self.input,
            "result": self.result,
            "error": self.error,
            "meta": {
                "risk_level": self.meta.risk_level,
                "aggressive": self.meta.aggressive,
                "duration_ms": self.meta.duration_ms,
                "timestamp": self.meta.timestamp,
                "version": self.meta.version,
            },
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

