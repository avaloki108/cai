from __future__ import annotations

import json
import os
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from time import monotonic
from typing import Any, Dict

from cai.sdk.agents import function_tool
from cai.tools.web3_security.plugin_registry import REGISTRY
from cai.tools.web3_security.policy import (
    evaluate_policy,
    is_plugin_exposed,
    parse_policy_level,
)
from cai.tools.web3_security.schemas import (
    ExposureSurface,
    PluginRunMeta,
    PluginRunRequest,
    PluginRunResponse,
    utc_now_iso,
)


def _normalize_result(result: Any) -> Dict[str, Any]:
    if result is None:
        return {}
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            return {"value": result}
    return {"value": result}


def list_plugins(surface: ExposureSurface = ExposureSurface.AGENT) -> Dict[str, Any]:
    plugins = []
    for plugin in REGISTRY.list():
        metadata = plugin.metadata
        if not is_plugin_exposed(metadata.name, surface):
            continue
        plugins.append(
            {
                "name": metadata.name,
                "description": metadata.description,
                "category": metadata.category,
                "risk_level": metadata.risk_level.value,
                "requires_aggressive": metadata.requires_aggressive,
                "supports_fork_test": metadata.supports_fork_test,
                "supports_formal_verification": metadata.supports_formal_verification,
                "mutates_state": metadata.mutates_state,
                "chain_type": metadata.chain_type.value,
            }
        )
    return {"plugins": sorted(plugins, key=lambda p: p["name"])}


def describe_plugin(plugin_name: str) -> Dict[str, Any]:
    plugin = REGISTRY.get(plugin_name)
    metadata = plugin.metadata
    return {
        "name": metadata.name,
        "description": metadata.description,
        "category": metadata.category,
        "risk_level": metadata.risk_level.value,
        "requires_aggressive": metadata.requires_aggressive,
        "input_schema": metadata.input_schema,
        "supports_fork_test": metadata.supports_fork_test,
        "supports_formal_verification": metadata.supports_formal_verification,
        "mutates_state": metadata.mutates_state,
        "chain_type": metadata.chain_type.value,
    }


def run_plugin(request: PluginRunRequest) -> Dict[str, Any]:
    request_id = uuid.uuid4().hex
    started = monotonic()
    plugin = REGISTRY.get(request.plugin_name)
    metadata = plugin.metadata
    policy_level = parse_policy_level(request.policy_level)

    if not is_plugin_exposed(metadata.name, request.exposure_surface):
        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=False,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result=None,
            error={
                "type": "exposure_blocked",
                "message": f"Plugin '{metadata.name}' is not exposed on surface '{request.exposure_surface.value}'.",
            },
            meta=meta,
        )
        return response.to_dict()

    allowed, reason, required_flags = evaluate_policy(
        metadata=metadata,
        policy_level=policy_level,
        allow_aggressive=request.allow_aggressive,
    )
    if not allowed:
        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=False,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result={
                "dry_run": request.dry_run,
                "allowed": False,
                "required_flags": required_flags,
            },
            error={"type": "policy_blocked", "message": reason},
            meta=meta,
        )
        return response.to_dict()

    if request.dry_run:
        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=True,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result={
                "dry_run": True,
                "allowed": True,
                "required_flags": required_flags,
                "expected_input_schema": metadata.input_schema,
            },
            error=None,
            meta=meta,
        )
        return response.to_dict()

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(plugin.execute, request.args)
            raw_result = future.result(timeout=max(1, int(request.timeout_sec)))
        result = _normalize_result(raw_result)
        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=True,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result=result,
            error=None,
            meta=meta,
        )
        return response.to_dict()
    except FutureTimeout:
        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=False,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result=None,
            error={
                "type": "timeout",
                "message": f"Plugin execution exceeded timeout ({request.timeout_sec}s).",
            },
            meta=meta,
        )
        return response.to_dict()
    except Exception as exc:  # pylint: disable=broad-except
        include_trace = os.getenv("CAI_DEBUG", "1") == "2"
        error = {
            "type": "execution_error",
            "message": str(exc),
        }
        if include_trace:
            error["traceback"] = traceback.format_exc()

        meta = PluginRunMeta(
            risk_level=metadata.risk_level.value,
            aggressive=bool(request.allow_aggressive),
            duration_ms=int((monotonic() - started) * 1000),
            timestamp=utc_now_iso(),
        )
        response = PluginRunResponse(
            ok=False,
            plugin=metadata.name,
            request_id=request_id,
            input=request.args,
            result=None,
            error=error,
            meta=meta,
        )
        return response.to_dict()


@function_tool(strict_mode=False)
def list_web3_plugins(surface: str = "agent") -> str:
    exposure = ExposureSurface(surface.lower())
    return json.dumps(list_plugins(exposure), ensure_ascii=True)


@function_tool(strict_mode=False)
def describe_web3_plugin(plugin_name: str) -> str:
    return json.dumps(describe_plugin(plugin_name), ensure_ascii=True)


@function_tool(strict_mode=False)
def run_web3_plugin(
    plugin_name: str,
    args: str = "{}",
    policy_level: str = "safe",
    allow_aggressive: bool = False,
    dry_run: bool = False,
    timeout_sec: int = 30,
    exposure_surface: str = "agent",
) -> str:
    parsed_args: Dict[str, Any]
    try:
        parsed = json.loads(args) if args else {}
        parsed_args = parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception as exc:
        return json.dumps(
            {
                "ok": False,
                "plugin": plugin_name,
                "request_id": uuid.uuid4().hex,
                "input": {"raw_args": args},
                "result": None,
                "error": {"type": "invalid_args", "message": str(exc)},
                "meta": {
                    "risk_level": "safe",
                    "aggressive": bool(allow_aggressive),
                    "duration_ms": 0,
                    "timestamp": utc_now_iso(),
                    "version": "1",
                },
            },
            ensure_ascii=True,
        )

    request = PluginRunRequest(
        plugin_name=plugin_name,
        args=parsed_args,
        policy_level=parse_policy_level(policy_level),
        allow_aggressive=allow_aggressive,
        dry_run=dry_run,
        timeout_sec=timeout_sec,
        exposure_surface=ExposureSurface(exposure_surface.lower()),
    )
    return json.dumps(run_plugin(request), ensure_ascii=True)

