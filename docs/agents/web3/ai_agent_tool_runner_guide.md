# AI Agent Guide: Web3 Plugin Runner

This guide is for AI agents operating in CAI who need to run Web3 plugin tools quickly and safely.

## What To Use

- `list_web3_plugins` to discover available runner-exposed plugins.
- `describe_web3_plugin` to read metadata and input schema.
- `run_web3_plugin` to execute with policy and safety controls.

The runner enforces:

- policy levels: `safe`, `balanced`, `aggressive`
- aggressive gating via `allow_aggressive`
- exposure allowlists (`agent` vs `mcp`)
- timeouts, request IDs, and structured error envelopes

## Recommended Agent Flow

1. List plugins.
2. Describe target plugin.
3. Run `dry_run=true` first.
4. If allowed, execute with explicit policy and timeout.
5. Use `request_id` and `meta` for correlation and retries.

## Agent Tool Call Pattern

Use this order in prompts/tool orchestration:

1. `list_web3_plugins(surface="agent")`
2. `describe_web3_plugin(plugin_name)`
3. `run_web3_plugin(plugin_name, args, policy_level="safe", dry_run=true)`
4. `run_web3_plugin(plugin_name, args, policy_level=..., allow_aggressive=..., dry_run=false)`

## REPL Usage (`/hunt plugins`)

```bash
/hunt plugins list
/hunt plugins describe false_positive_filter
/hunt plugins run false_positive_filter --args '{"findings":[]}' --policy safe --dry-run
/hunt plugins run false_positive_filter --args-file args.json --policy balanced
```

## MCP Usage

Load and bind the MCP server:

```bash
/mcp load stdio web3tools python -m cai.mcp.web3_tools_server
/mcp add web3tools web3_bug_bounty_agent
```

MCP tools:

- `list_web3_plugins()`
- `describe_web3_plugin(plugin_name)`
- `run_web3_plugin(plugin_name, args, policy_level="safe", allow_aggressive=false, dry_run=false)`

## Safety Defaults

- Start with `policy_level="safe"`.
- Keep `allow_aggressive=false` unless explicitly required.
- Always preflight with `dry_run=true`.
- Set explicit `timeout_sec` for long-running plugins.

## Output Envelope

`run_web3_plugin` returns a normalized envelope:

- `ok`
- `plugin`
- `request_id`
- `input`
- `result`
- `error`
- `meta` (`risk_level`, `aggressive`, `duration_ms`, `timestamp`, `version`)

Use `error.type` and `request_id` for deterministic retries and triage.

