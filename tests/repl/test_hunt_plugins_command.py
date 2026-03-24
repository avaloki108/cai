from __future__ import annotations

import json
import os

from cai.repl.commands.hunt import HuntCommand


def test_hunt_plugins_list(monkeypatch):
    command = HuntCommand()

    monkeypatch.setattr(
        "cai.repl.commands.hunt.list_plugins",
        lambda _surface: {"plugins": [{"name": "false_positive_filter"}]},
    )

    assert command.handle(["plugins", "list"]) is True


def test_hunt_plugins_describe(monkeypatch):
    command = HuntCommand()
    monkeypatch.setattr(
        "cai.repl.commands.hunt.describe_plugin",
        lambda plugin_name: {"name": plugin_name, "risk_level": "safe"},
    )
    assert command.handle(["plugins", "describe", "false_positive_filter"]) is True


def test_hunt_plugins_run_args_file(monkeypatch, tmp_path):
    command = HuntCommand()
    args_file = tmp_path / "args.json"
    args_file.write_text(json.dumps({"value": 1}), encoding="utf-8")

    captured = {}

    def fake_run_plugin(request):
        captured["plugin"] = request.plugin_name
        captured["args"] = request.args
        captured["dry_run"] = request.dry_run
        return {"ok": True, "plugin": request.plugin_name}

    monkeypatch.setattr("cai.repl.commands.hunt.run_plugin", fake_run_plugin)

    result = command.handle(
        [
            "plugins",
            "run",
            "false_positive_filter",
            "--args-file",
            str(args_file),
            "--dry-run",
        ]
    )

    assert result is True
    assert captured["plugin"] == "false_positive_filter"
    assert captured["args"] == {"value": 1}
    assert captured["dry_run"] is True


def test_hunt_sets_agent_workspace_and_auto_prompt(monkeypatch, tmp_path):
    command = HuntCommand()
    project_path = tmp_path / "doppler_02"
    project_path.mkdir()
    captured = {}

    def fake_handle_command(cmd, args):
        captured["cmd"] = cmd
        captured["args"] = args
        return True

    monkeypatch.setattr("cai.repl.commands.hunt.handle_command", fake_handle_command)
    monkeypatch.setenv("CAI_HUNT_AGENT", "web3_bug_bounty_agent")
    monkeypatch.delenv("CAI_HUNT_AUTO_PROMPT", raising=False)

    assert command.handle([str(project_path)]) is True
    assert captured["cmd"] == "/agent"
    assert captured["args"] == ["select", "web3_bug_bounty_agent"]
    assert os.environ["CAI_WORKSPACE"] == "doppler_02"
    assert os.environ["CAI_WORKSPACE_DIR"] == str(tmp_path)
    assert "Target path:" in os.environ["CAI_HUNT_AUTO_PROMPT"]
    assert str(project_path) in os.environ["CAI_HUNT_AUTO_PROMPT"]


def test_hunt_auto_start_can_be_disabled(monkeypatch, tmp_path):
    command = HuntCommand()
    project_path = tmp_path / "doppler_02"
    project_path.mkdir()

    monkeypatch.setattr("cai.repl.commands.hunt.handle_command", lambda _cmd, _args: True)
    monkeypatch.setenv("CAI_HUNT_AUTO_START", "false")
    monkeypatch.setenv("CAI_HUNT_AUTO_PROMPT", "stale")

    assert command.handle([str(project_path)]) is True
    assert "CAI_HUNT_AUTO_PROMPT" not in os.environ

