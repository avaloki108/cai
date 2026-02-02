"""
Auto Report Generation Hooks for CAI Agents

This module provides lifecycle hooks that automatically generate and save
comprehensive reports when agents complete their tasks.

Usage:
    from cai.sdk.agents import Runner, RunConfig
    from cai.sdk.agents.auto_report_hooks import AutoReportHooks
    
    # Enable auto-reporting via hooks
    hooks = AutoReportHooks()
    result = await Runner.run(agent, input, hooks=hooks)
    
    # Or use the convenience function
    from cai.sdk.agents.auto_report_hooks import create_auto_report_runner
    result = await create_auto_report_runner(agent, input)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Generic

from .agent import Agent
from .lifecycle import RunHooks
from .run_context import RunContextWrapper, TContext
from .tool import Tool
from .report_generator import (
    ReportConfig,
    get_report_config,
    generate_and_save_report,
    generate_and_save_report_sync,
)

logger = logging.getLogger(__name__)


class AutoReportHooks(RunHooks[TContext], Generic[TContext]):
    """
    Lifecycle hooks that automatically generate reports when agents complete.
    
    This hooks class tracks agent execution and generates a comprehensive
    report upon completion, saving it to the configured report directory.
    
    Attributes:
        config: Report generation configuration
        start_time: When the agent run started
        report_path: Path to the generated report (available after completion)
    """
    
    def __init__(
        self,
        config: ReportConfig | None = None,
        enabled: bool | None = None,
    ):
        """
        Initialize the auto-report hooks.
        
        Args:
            config: Optional report configuration. If not provided, uses
                    environment variables.
            enabled: Override the enabled setting. If None, uses config.
        """
        super().__init__()
        self.config = config or get_report_config()
        
        # Allow explicit override of enabled status
        if enabled is not None:
            self.config.enabled = enabled
            
        self.start_time: datetime | None = None
        self.report_path: str | None = None
        self._current_agent: Agent | None = None
        self._tools_used: list[str] = []
        
    async def on_agent_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext]
    ) -> None:
        """Called when an agent starts. Records the start time."""
        if self.start_time is None:
            self.start_time = datetime.now()
        self._current_agent = agent
        logger.debug(f"Auto-report: Agent '{agent.name}' started")
        
    async def on_agent_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        output: Any,
    ) -> None:
        """Called when an agent completes. Generates and saves the report."""
        if not self.config.enabled:
            return
            
        logger.debug(f"Auto-report: Agent '{agent.name}' completed, generating report...")
        
        # We need to construct a minimal result-like object from the available data
        # The actual RunResult will be constructed by the Runner after this hook
        # So we store the info and let the post-run hook handle it
        self._current_agent = agent
        
    async def on_tool_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
    ) -> None:
        """Track tool usage for the report."""
        if tool.name not in self._tools_used:
            self._tools_used.append(tool.name)
            
    async def on_tool_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
        result: str,
    ) -> None:
        """Called after a tool completes."""
        pass  # Tool is already tracked in on_tool_start
        
    async def on_handoff(
        self,
        context: RunContextWrapper[TContext],
        from_agent: Agent[TContext],
        to_agent: Agent[TContext],
    ) -> None:
        """Track handoffs between agents."""
        logger.debug(f"Auto-report: Handoff from '{from_agent.name}' to '{to_agent.name}'")
        
    def generate_report_for_result(self, result: Any, agent: Agent | None = None) -> str | None:
        """
        Generate a report for a completed run result.
        
        This should be called after Runner.run() completes with the result.
        
        Args:
            result: The RunResult from Runner.run()
            agent: Optional agent override (uses last_agent from result if not provided)
            
        Returns:
            Path to the saved report, or None if disabled/failed
        """
        if not self.config.enabled:
            return None
            
        # Get the agent from result if not provided
        if agent is None:
            agent = getattr(result, 'last_agent', self._current_agent)
            
        if agent is None:
            logger.warning("Auto-report: No agent available for report generation")
            return None
            
        try:
            self.report_path = generate_and_save_report_sync(
                result=result,
                agent=agent,
                config=self.config,
                start_time=self.start_time,
            )
            
            if self.report_path:
                logger.info(f"Auto-report: Report saved to {self.report_path}")
            return self.report_path
            
        except Exception as e:
            logger.error(f"Auto-report: Failed to generate report: {e}")
            return None


class CombinedHooks(RunHooks[TContext], Generic[TContext]):
    """
    Combines multiple hook instances into one.
    
    This allows using AutoReportHooks alongside other custom hooks.
    """
    
    def __init__(self, *hooks: RunHooks[TContext]):
        """
        Initialize with multiple hook instances.
        
        Args:
            *hooks: Variable number of RunHooks instances to combine
        """
        super().__init__()
        self.hooks = list(hooks)
        
    async def on_agent_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext]
    ) -> None:
        for hook in self.hooks:
            await hook.on_agent_start(context, agent)
            
    async def on_agent_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        output: Any,
    ) -> None:
        for hook in self.hooks:
            await hook.on_agent_end(context, agent, output)
            
    async def on_handoff(
        self,
        context: RunContextWrapper[TContext],
        from_agent: Agent[TContext],
        to_agent: Agent[TContext],
    ) -> None:
        for hook in self.hooks:
            await hook.on_handoff(context, from_agent, to_agent)
            
    async def on_tool_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
    ) -> None:
        for hook in self.hooks:
            await hook.on_tool_start(context, agent, tool)
            
    async def on_tool_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
        result: str,
    ) -> None:
        for hook in self.hooks:
            await hook.on_tool_end(context, agent, tool, result)


def get_auto_report_hooks(
    existing_hooks: RunHooks | None = None,
    config: ReportConfig | None = None,
) -> RunHooks:
    """
    Get hooks with auto-report functionality.
    
    If existing hooks are provided, combines them with auto-report hooks.
    If auto-reporting is disabled via environment, returns existing hooks unchanged.
    
    Args:
        existing_hooks: Optional existing hooks to combine with
        config: Optional report configuration
        
    Returns:
        RunHooks instance with auto-report functionality
    """
    report_config = config or get_report_config()
    
    if not report_config.enabled:
        return existing_hooks or RunHooks()
        
    auto_hooks = AutoReportHooks(config=report_config)
    
    if existing_hooks is None:
        return auto_hooks
        
    return CombinedHooks(existing_hooks, auto_hooks)


async def run_with_auto_report(
    starting_agent: Agent[TContext],
    input: str | list,
    *,
    context: TContext | None = None,
    max_turns: int | float = float("inf"),
    hooks: RunHooks[TContext] | None = None,
    run_config: Any | None = None,
    report_config: ReportConfig | None = None,
) -> tuple[Any, str | None]:
    """
    Convenience function to run an agent with automatic report generation.
    
    Args:
        starting_agent: The agent to run
        input: The input to the agent
        context: Optional context
        max_turns: Maximum number of turns
        hooks: Optional additional hooks (will be combined with auto-report hooks)
        run_config: Optional RunConfig
        report_config: Optional report configuration
        
    Returns:
        Tuple of (RunResult, report_path or None)
    """
    from .run import Runner
    
    # Get combined hooks with auto-report
    auto_hooks = get_auto_report_hooks(hooks, report_config)
    
    # Run the agent
    result = await Runner.run(
        starting_agent,
        input,
        context=context,
        max_turns=int(max_turns) if max_turns != float("inf") else max_turns,
        hooks=auto_hooks,
        run_config=run_config,
    )
    
    # Generate report if hooks support it
    report_path = None
    if isinstance(auto_hooks, AutoReportHooks):
        report_path = auto_hooks.generate_report_for_result(result)
    elif isinstance(auto_hooks, CombinedHooks):
        for hook in auto_hooks.hooks:
            if isinstance(hook, AutoReportHooks):
                report_path = hook.generate_report_for_result(result)
                break
                
    return result, report_path
