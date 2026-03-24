from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class CallbackEvent:
    token: str
    channel: str
    source: str
    payload: str
    seen_at: str = field(default_factory=_utc_now)


@dataclass
class EngagementState:
    """
    Run-scoped context for autonomous exploitation campaigns.

    This object is designed to be mutable during a run and never sent
    to the model directly. It is for tools/hooks/runtime coordination.
    """

    run_id: Optional[str] = None
    targets: Set[str] = field(default_factory=set)
    discovered_endpoints: Set[str] = field(default_factory=set)
    identities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tokens: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    callback_tokens: Set[str] = field(default_factory=set)
    callback_events: List[CallbackEvent] = field(default_factory=list)
    payload_attempts: List[Dict[str, Any]] = field(default_factory=list)
    finding_links: Dict[str, List[str]] = field(default_factory=dict)

    def add_target(self, target: str) -> None:
        if target:
            self.targets.add(target)

    def add_endpoint(self, endpoint: str) -> None:
        if endpoint:
            self.discovered_endpoints.add(endpoint)

    def record_payload_attempt(
        self,
        module: str,
        target: str,
        payload: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        item = {
            "at": _utc_now(),
            "module": module,
            "target": target,
            "payload": payload,
        }
        if extra:
            item["extra"] = extra
        self.payload_attempts.append(item)

    def register_callback_token(self, token: str) -> None:
        if token:
            self.callback_tokens.add(token)

    def add_callback_event(
        self,
        token: str,
        channel: str,
        source: str,
        payload: str,
    ) -> None:
        self.callback_events.append(
            CallbackEvent(
                token=token,
                channel=channel,
                source=source,
                payload=payload,
            )
        )

    def link_finding(self, finding_id: str, evidence_id: str) -> None:
        if not finding_id or not evidence_id:
            return
        self.finding_links.setdefault(finding_id, []).append(evidence_id)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "targets": sorted(self.targets),
            "discovered_endpoints": sorted(self.discovered_endpoints),
            "identities": self.identities,
            "tokens": self.tokens,
            "callback_tokens": sorted(self.callback_tokens),
            "callback_events": [
                {
                    "token": e.token,
                    "channel": e.channel,
                    "source": e.source,
                    "payload": e.payload,
                    "seen_at": e.seen_at,
                }
                for e in self.callback_events
            ],
            "payload_attempts": self.payload_attempts,
            "finding_links": self.finding_links,
        }
