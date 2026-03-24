from __future__ import annotations

import time

import pytest

import cai.tools.web3_security.policy as policy_module
from cai.tools.web3_security.plugin_registry import REGISTRY
from cai.tools.web3_security.runner import describe_plugin, list_plugins, run_plugin
from cai.tools.web3_security.schemas import (
    ChainType,
    ExposureSurface,
    PluginRunRequest,
    RiskLevel,
    Web3Plugin,
    Web3PluginMetadata,
)


@pytest.fixture
def temporary_plugin(monkeypatch):
    metadata = Web3PluginMetadata(
        name="temp_test_plugin",
        description="Temporary test plugin",
        category="testing",
        risk_level=RiskLevel.BALANCED,
        requires_aggressive=False,
        input_schema={"type": "object", "properties": {"value": {"type": "integer"}}},
        supports_fork_test=False,
        supports_formal_verification=False,
        mutates_state=False,
        chain_type=ChainType.EVM,
    )

    def execute(args):
        return {"echo": args.get("value", 0)}

    REGISTRY.register(Web3Plugin(metadata=metadata, execute=execute))
    monkeypatch.setattr(
        policy_module,
        "AGENT_EXPOSED_PLUGINS",
        set(policy_module.AGENT_EXPOSED_PLUGINS) | {"temp_test_plugin"},
    )
    yield metadata.name
    REGISTRY.unregister(metadata.name)


def test_list_and_describe_plugin(temporary_plugin):
    listed = list_plugins(ExposureSurface.AGENT)
    names = {item["name"] for item in listed["plugins"]}
    assert temporary_plugin in names

    described = describe_plugin(temporary_plugin)
    assert described["name"] == temporary_plugin
    assert described["risk_level"] == "balanced"


def test_run_plugin_dry_run(temporary_plugin):
    response = run_plugin(
        PluginRunRequest(
            plugin_name=temporary_plugin,
            args={"value": 7},
            policy_level=RiskLevel.BALANCED,
            dry_run=True,
            exposure_surface=ExposureSurface.AGENT,
        )
    )
    assert response["ok"] is True
    assert response["result"]["dry_run"] is True
    assert response["request_id"]


def test_run_plugin_executes_successfully(temporary_plugin):
    response = run_plugin(
        PluginRunRequest(
            plugin_name=temporary_plugin,
            args={"value": 9},
            policy_level=RiskLevel.BALANCED,
            exposure_surface=ExposureSurface.AGENT,
        )
    )
    assert response["ok"] is True
    assert response["result"]["echo"] == 9
    assert response["meta"]["risk_level"] == "balanced"


def test_run_plugin_timeout(monkeypatch):
    metadata = Web3PluginMetadata(
        name="temp_timeout_plugin",
        description="Timeout plugin",
        category="testing",
        risk_level=RiskLevel.SAFE,
        requires_aggressive=False,
        input_schema={"type": "object", "properties": {}},
        supports_fork_test=False,
        supports_formal_verification=False,
        mutates_state=False,
        chain_type=ChainType.EVM,
    )

    def execute(_args):
        time.sleep(2)
        return {"ok": True}

    REGISTRY.register(Web3Plugin(metadata=metadata, execute=execute))
    monkeypatch.setattr(
        policy_module,
        "AGENT_EXPOSED_PLUGINS",
        set(policy_module.AGENT_EXPOSED_PLUGINS) | {"temp_timeout_plugin"},
    )

    response = run_plugin(
        PluginRunRequest(
            plugin_name="temp_timeout_plugin",
            args={},
            policy_level=RiskLevel.SAFE,
            timeout_sec=1,
            exposure_surface=ExposureSurface.AGENT,
        )
    )
    assert response["ok"] is False
    assert response["error"]["type"] == "timeout"
    REGISTRY.unregister("temp_timeout_plugin")

