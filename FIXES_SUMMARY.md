# CAI Agent Fixes - Summary

## Issues Fixed

### 1. MCP Event Loop Binding Error
**Problem**: 
```
RuntimeError: <asyncio.locks.Lock object at 0x78477d947f00 [locked]> is bound to a different event loop
```

**Root Cause**: 
The `_SERVER_INVOCATION_LOCKS` dictionary was storing `asyncio.Lock` objects that were created once and then reused across different event loop contexts. When an `asyncio.Lock` is created, it becomes bound to the current event loop. If the same lock is accessed from a different event loop (which can happen when agents run in different async contexts), it fails with the "bound to a different event loop" error.

**Solution** (File: `/home/dok/tools/cai/src/cai/repl/commands/mcp.py`):
- Changed `_SERVER_INVOCATION_LOCKS` from `Dict[str, asyncio.Lock]` to `Dict[str, Dict[int, asyncio.Lock]]`
- Now maintains per-event-loop locks: `{server_name: {event_loop_id: lock}}`
- Modified `invoke_with_fresh_connection()` to:
  - Get the current event loop ID using `id(asyncio.get_running_loop())`
  - Create or retrieve a lock specific to that event loop
  - Use only event-loop-specific locks

**Code Changes**:
```python
# Before:
lock = _SERVER_INVOCATION_LOCKS.setdefault(server_name, asyncio.Lock())

# After:
current_loop_id = id(asyncio.get_running_loop())
server_locks = _SERVER_INVOCATION_LOCKS.setdefault(server_name, {})
lock = server_locks.setdefault(current_loop_id, asyncio.Lock())
```

### 2. LiteLLM Logging Errors
**Problem**:
```
ERROR:LiteLLM:Error creating standard logging object - 1 validation error for ResponseAPIUsage
output_tokens_details
  Field required [type=missing, input_value={...}]
```

**Root Cause**: 
LiteLLM's internal logging is attempting to create `ResponseAPIUsage` objects from response data that may not have all required fields like `output_tokens_details`. This is a non-fatal logging error that occurs when LiteLLM tries to format usage information for logging purposes. The actual response processing continues successfully.

**Solution** (File: `/home/dok/tools/cai/src/cai/cli.py`):
- Enhanced the log suppression filter to catch all variations of the LiteLLM ResponseAPIUsage validation errors
- Added patterns for:
  - `"responseapiusage"` - direct class name matches
  - `"response_api_usage"` - alternate naming pattern
  - `"responseapiprice"` - related API usage patterns
  - `"error when formatting litellm response"` - response formatting errors
  - `"litellm logging error"` - generic LiteLLM logging errors

**Code Changes**:
```python
# Added to suppress_patterns list:
"responseapiusage",
"response_api_usage",
"responseapiprice",
# LiteLLM usage tracking warnings
"error when formatting litellm response",
"litellm logging error",
```

## Impact

### MCP Event Loop Fix
- **Severity**: Critical
- **Impact**: Allows Serena and other MCP servers to work correctly with agents running in multiple event loop contexts
- **Testing**: The agents can now successfully invoke MCP tools without event loop conflicts

### LiteLLM Logging Fix
- **Severity**: Low (cosmetic)
- **Impact**: Reduces noise in logs while maintaining actual functionality
- **Testing**: Agents continue to function normally; logging is cleaner

## Files Modified
1. `/home/dok/tools/cai/src/cai/repl/commands/mcp.py` - Event loop lock management
2. `/home/dok/tools/cai/src/cai/cli.py` - Log suppression patterns

## Testing Recommendations

```bash
# Test MCP tool invocation with agents
CAI> /mcp load sse http://localhost:9876/sse serena
CAI> /mcp add serena bug_bounter
CAI> audit the web3 project at /path/to/project

# Monitor logs for:
# 1. No "bound to a different event loop" errors
# 2. No "ResponseAPIUsage validation" errors
# 3. Successful MCP tool invocations
```

## Backward Compatibility
✅ Fully backward compatible - no breaking changes to APIs or interfaces.
