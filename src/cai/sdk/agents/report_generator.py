"""
Auto Report Generator for CAI Agents

This module provides automatic report generation functionality for agents
upon completion of audits or tasks. Reports are saved to a local `.cai/`
directory with standardized naming conventions.

Environment Variables:
    CAI_AUTO_REPORT: Enable/disable auto report generation (default: "true")
    CAI_REPORT_DIR: Custom report directory (default: ".cai")
    CAI_REPORT_FORMAT: Report format - "md", "json", "html" (default: "md")
"""
from __future__ import annotations

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING
from dataclasses import dataclass, field, asdict

if TYPE_CHECKING:
    from .agent import Agent
    from .result import RunResult, RunResultStreaming
    from .items import RunItem

logger = logging.getLogger(__name__)


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    agent_name: str
    task_type: str
    timestamp: str
    duration_seconds: float | None = None
    model_used: str | None = None
    total_turns: int = 0
    tools_used: list[str] = field(default_factory=list)
    input_summary: str = ""
    success: bool = True
    error_message: str | None = None


@dataclass 
class ReportConfig:
    """Configuration for report generation."""
    enabled: bool = True
    report_dir: str = ".cai"
    format: str = "md"  # md, json, html
    include_tool_outputs: bool = True
    include_raw_responses: bool = False
    max_content_length: int = 50000  # Truncate very long outputs
    

def get_report_config() -> ReportConfig:
    """Get report configuration from environment variables."""
    return ReportConfig(
        enabled=os.getenv("CAI_AUTO_REPORT", "true").lower() in ("true", "1", "yes"),
        report_dir=os.getenv("CAI_REPORT_DIR", ".cai"),
        format=os.getenv("CAI_REPORT_FORMAT", "md").lower(),
        include_tool_outputs=os.getenv("CAI_REPORT_TOOL_OUTPUTS", "true").lower() in ("true", "1", "yes"),
        include_raw_responses=os.getenv("CAI_REPORT_RAW_RESPONSES", "false").lower() in ("true", "1", "yes"),
    )


def ensure_report_directory(report_dir: str = ".cai") -> Path:
    """
    Ensure the report directory exists, creating it if necessary.
    
    Args:
        report_dir: The directory path for storing reports
        
    Returns:
        Path object for the report directory
    """
    report_path = Path(report_dir)
    
    # Handle relative paths - make them relative to current working directory
    if not report_path.is_absolute():
        report_path = Path.cwd() / report_path
    
    try:
        report_path.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Report directory ensured: {report_path}")
    except PermissionError as e:
        logger.error(f"Permission denied creating report directory: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to create report directory: {e}")
        raise
        
    return report_path


def generate_report_filename(
    agent_name: str,
    task_type: str = "task",
    extension: str = "md"
) -> str:
    """
    Generate a standardized report filename.
    
    Format: {timestamp}_{agent_name}_{task_type}.{extension}
    Example: 2026-02-01_143052_web3_auditor_audit.md
    
    Args:
        agent_name: Name of the agent that produced the report
        task_type: Type of task (audit, analysis, scan, etc.)
        extension: File extension (md, json, html)
        
    Returns:
        Standardized filename string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    
    # Sanitize agent name for filesystem
    safe_agent_name = "".join(
        c if c.isalnum() or c in "-_" else "_" 
        for c in agent_name.lower().replace(" ", "_")
    )
    
    # Sanitize task type
    safe_task_type = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in task_type.lower().replace(" ", "_")
    )
    
    return f"{timestamp}_{safe_agent_name}_{safe_task_type}.{extension}"


def extract_task_type(agent_name: str, final_output: Any) -> str:
    """
    Determine the task type based on agent name and output.
    
    Args:
        agent_name: Name of the agent
        final_output: The agent's final output
        
    Returns:
        Task type string (audit, analysis, scan, report, task)
    """
    agent_lower = agent_name.lower()
    
    # Map agent names to task types
    task_type_mappings = {
        "audit": ["auditor", "audit", "security"],
        "scan": ["scanner", "scan", "recon"],
        "analysis": ["analyzer", "analysis", "exploit"],
        "report": ["reporter", "report"],
        "bounty": ["bounty", "bug_bounty", "hunter"],
        "pentest": ["pentest", "red_team", "redteam"],
    }
    
    for task_type, keywords in task_type_mappings.items():
        for keyword in keywords:
            if keyword in agent_lower:
                return task_type
    
    return "task"


def extract_tools_used(items: list) -> list[str]:
    """Extract list of tools used from run items."""
    tools = set()
    for item in items:
        if hasattr(item, 'type') and item.type == 'tool_call_item':
            if hasattr(item, 'raw_item') and hasattr(item.raw_item, 'name'):
                tools.add(item.raw_item.name)
        elif hasattr(item, 'call_id') and hasattr(item, 'name'):
            tools.add(item.name)
    return sorted(list(tools))


def format_input_summary(input_data: str | list, max_length: int = 500) -> str:
    """Create a summary of the input data."""
    if isinstance(input_data, str):
        text = input_data
    elif isinstance(input_data, list):
        # Extract text content from list of input items
        parts = []
        for item in input_data:
            if isinstance(item, dict):
                content = item.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
            elif isinstance(item, str):
                parts.append(item)
        text = " ".join(parts)
    else:
        text = str(input_data)
    
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


def generate_markdown_report(
    result: "RunResult | RunResultStreaming",
    agent: "Agent",
    metadata: ReportMetadata,
    config: ReportConfig
) -> str:
    """
    Generate a comprehensive markdown report from agent results.
    
    Args:
        result: The RunResult or RunResultStreaming object
        agent: The agent that produced the result
        metadata: Report metadata
        config: Report configuration
        
    Returns:
        Markdown formatted report string
    """
    lines = []
    
    # Header
    lines.append(f"# {metadata.agent_name} - {metadata.task_type.title()} Report")
    lines.append("")
    lines.append(f"**Generated:** {metadata.timestamp}")
    lines.append(f"**Status:** {'Success' if metadata.success else 'Failed'}")
    if metadata.model_used:
        lines.append(f"**Model:** {metadata.model_used}")
    lines.append(f"**Total Turns:** {metadata.total_turns}")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    if metadata.input_summary:
        lines.append(f"**Task:** {metadata.input_summary}")
        lines.append("")
    
    # Final Output
    lines.append("## Final Output")
    lines.append("")
    if result.final_output:
        output_str = str(result.final_output)
        if len(output_str) > config.max_content_length:
            output_str = output_str[:config.max_content_length] + "\n\n[Output truncated...]"
        lines.append(output_str)
    else:
        lines.append("*No final output generated*")
    lines.append("")
    
    # Tools Used
    if metadata.tools_used:
        lines.append("## Tools Used")
        lines.append("")
        for tool in metadata.tools_used:
            lines.append(f"- `{tool}`")
        lines.append("")
    
    # Execution Details
    if config.include_tool_outputs and result.new_items:
        lines.append("## Execution Details")
        lines.append("")
        
        for idx, item in enumerate(result.new_items, 1):
            item_type = getattr(item, 'type', 'unknown')
            
            if item_type == 'message_output_item':
                content = ""
                if hasattr(item, 'raw_item'):
                    raw = item.raw_item
                    if hasattr(raw, 'content') and raw.content:
                        for part in raw.content:
                            if hasattr(part, 'text'):
                                content = part.text
                                break
                if content:
                    lines.append(f"### Step {idx}: Assistant Message")
                    lines.append("")
                    if len(content) > 2000:
                        content = content[:2000] + "\n\n[Truncated...]"
                    lines.append(content)
                    lines.append("")
                    
            elif item_type == 'tool_call_item':
                tool_name = "unknown"
                if hasattr(item, 'raw_item') and hasattr(item.raw_item, 'name'):
                    tool_name = item.raw_item.name
                lines.append(f"### Step {idx}: Tool Call - `{tool_name}`")
                lines.append("")
                if hasattr(item, 'raw_item') and hasattr(item.raw_item, 'arguments'):
                    args = item.raw_item.arguments
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            pass
                    if isinstance(args, dict):
                        lines.append("**Arguments:**")
                        lines.append("```json")
                        args_str = json.dumps(args, indent=2)
                        if len(args_str) > 1000:
                            args_str = args_str[:1000] + "\n..."
                        lines.append(args_str)
                        lines.append("```")
                lines.append("")
                
            elif item_type == 'tool_call_output_item':
                lines.append(f"### Step {idx}: Tool Output")
                lines.append("")
                if hasattr(item, 'output'):
                    output = str(item.output)
                    if len(output) > 2000:
                        output = output[:2000] + "\n\n[Output truncated...]"
                    lines.append("```")
                    lines.append(output)
                    lines.append("```")
                lines.append("")
    
    # Guardrail Results
    if result.input_guardrail_results or result.output_guardrail_results:
        lines.append("## Guardrail Results")
        lines.append("")
        
        if result.input_guardrail_results:
            lines.append("### Input Guardrails")
            for gr in result.input_guardrail_results:
                name = gr.guardrail.get_name() if hasattr(gr.guardrail, 'get_name') else str(gr.guardrail)
                triggered = gr.output.tripwire_triggered if hasattr(gr.output, 'tripwire_triggered') else False
                status = "Triggered" if triggered else "Passed"
                lines.append(f"- **{name}:** {status}")
            lines.append("")
            
        if result.output_guardrail_results:
            lines.append("### Output Guardrails")
            for gr in result.output_guardrail_results:
                name = gr.guardrail.get_name() if hasattr(gr.guardrail, 'get_name') else str(gr.guardrail)
                triggered = gr.output.tripwire_triggered if hasattr(gr.output, 'tripwire_triggered') else False
                status = "Triggered" if triggered else "Passed"
                lines.append(f"- **{name}:** {status}")
            lines.append("")
    
    # Error Information
    if not metadata.success and metadata.error_message:
        lines.append("## Error Information")
        lines.append("")
        lines.append(f"```\n{metadata.error_message}\n```")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append(f"*Report generated by CAI Auto-Report System*")
    
    return "\n".join(lines)


def generate_json_report(
    result: "RunResult | RunResultStreaming",
    agent: "Agent",
    metadata: ReportMetadata,
    config: ReportConfig
) -> str:
    """Generate a JSON formatted report."""
    report_data = {
        "metadata": asdict(metadata),
        "final_output": str(result.final_output) if result.final_output else None,
        "guardrails": {
            "input": [
                {
                    "name": gr.guardrail.get_name() if hasattr(gr.guardrail, 'get_name') else str(gr.guardrail),
                    "triggered": gr.output.tripwire_triggered if hasattr(gr.output, 'tripwire_triggered') else False
                }
                for gr in result.input_guardrail_results
            ],
            "output": [
                {
                    "name": gr.guardrail.get_name() if hasattr(gr.guardrail, 'get_name') else str(gr.guardrail),
                    "triggered": gr.output.tripwire_triggered if hasattr(gr.output, 'tripwire_triggered') else False
                }
                for gr in result.output_guardrail_results
            ]
        }
    }
    
    if config.include_tool_outputs:
        report_data["execution_steps"] = []
        for item in result.new_items:
            step = {"type": getattr(item, 'type', 'unknown')}
            if hasattr(item, 'raw_item'):
                if hasattr(item.raw_item, 'name'):
                    step["tool_name"] = item.raw_item.name
                if hasattr(item.raw_item, 'arguments'):
                    step["arguments"] = item.raw_item.arguments
            if hasattr(item, 'output'):
                output = str(item.output)
                if len(output) > config.max_content_length:
                    output = output[:config.max_content_length] + "...[truncated]"
                step["output"] = output
            report_data["execution_steps"].append(step)
    
    return json.dumps(report_data, indent=2, default=str)


def generate_html_report(
    result: "RunResult | RunResultStreaming",
    agent: "Agent",
    metadata: ReportMetadata,
    config: ReportConfig
) -> str:
    """Generate an HTML formatted report."""
    # Convert markdown to basic HTML
    md_content = generate_markdown_report(result, agent, metadata, config)
    
    html_lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        f"<title>{metadata.agent_name} - {metadata.task_type.title()} Report</title>",
        "<style>",
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; }",
        "h1, h2, h3 { color: #333; }",
        "code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }",
        "pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }",
        ".success { color: #28a745; }",
        ".failed { color: #dc3545; }",
        ".metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }",
        "</style>",
        "</head>",
        "<body>",
    ]
    
    # Basic markdown to HTML conversion
    in_code_block = False
    for line in md_content.split("\n"):
        if line.startswith("```"):
            if in_code_block:
                html_lines.append("</pre>")
                in_code_block = False
            else:
                html_lines.append("<pre>")
                in_code_block = True
        elif in_code_block:
            html_lines.append(line.replace("<", "&lt;").replace(">", "&gt;"))
        elif line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.startswith("**") and line.endswith("**"):
            html_lines.append(f"<strong>{line[2:-2]}</strong>")
        elif line.startswith("*") and line.endswith("*"):
            html_lines.append(f"<em>{line[1:-1]}</em>")
        elif line.strip() == "---":
            html_lines.append("<hr>")
        elif line.strip():
            html_lines.append(f"<p>{line}</p>")
    
    html_lines.extend([
        "</body>",
        "</html>"
    ])
    
    return "\n".join(html_lines)


async def generate_and_save_report(
    result: "RunResult | RunResultStreaming",
    agent: "Agent",
    config: ReportConfig | None = None,
    start_time: datetime | None = None,
) -> str | None:
    """
    Generate and save a comprehensive report from agent results.
    
    This is the main entry point for auto-report generation.
    
    Args:
        result: The RunResult or RunResultStreaming object
        agent: The agent that produced the result
        config: Optional report configuration (uses env vars if not provided)
        start_time: Optional start time for duration calculation
        
    Returns:
        Path to the saved report file, or None if generation is disabled
    """
    if config is None:
        config = get_report_config()
    
    if not config.enabled:
        logger.debug("Auto-report generation is disabled")
        return None
    
    try:
        # Ensure report directory exists
        report_dir = ensure_report_directory(config.report_dir)
        
        # Extract metadata
        agent_name = getattr(agent, 'name', 'unknown_agent')
        task_type = extract_task_type(agent_name, result.final_output)
        
        # Determine model used
        model_used = None
        if hasattr(agent, 'model'):
            if isinstance(agent.model, str):
                model_used = agent.model
            elif hasattr(agent.model, 'model'):
                model_used = agent.model.model
        
        # Calculate duration
        duration = None
        if start_time:
            duration = (datetime.now() - start_time).total_seconds()
        
        # Get turn count
        total_turns = 0
        if hasattr(result, 'current_turn'):
            total_turns = result.current_turn
        elif hasattr(result, 'raw_responses'):
            total_turns = len(result.raw_responses)
        
        metadata = ReportMetadata(
            agent_name=agent_name,
            task_type=task_type,
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            model_used=model_used,
            total_turns=total_turns,
            tools_used=extract_tools_used(result.new_items),
            input_summary=format_input_summary(result.input),
            success=result.final_output is not None,
        )
        
        # Generate report content based on format
        if config.format == "json":
            content = generate_json_report(result, agent, metadata, config)
            extension = "json"
        elif config.format == "html":
            content = generate_html_report(result, agent, metadata, config)
            extension = "html"
        else:  # Default to markdown
            content = generate_markdown_report(result, agent, metadata, config)
            extension = "md"
        
        # Generate filename and save
        filename = generate_report_filename(agent_name, task_type, extension)
        report_path = report_dir / filename
        
        report_path.write_text(content, encoding="utf-8")
        logger.info(f"Report saved: {report_path}")
        
        return str(report_path)
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        return None


def generate_and_save_report_sync(
    result: "RunResult | RunResultStreaming",
    agent: "Agent",
    config: ReportConfig | None = None,
    start_time: datetime | None = None,
) -> str | None:
    """Synchronous wrapper for generate_and_save_report."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're in an async context, create a task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    generate_and_save_report(result, agent, config, start_time)
                )
                return future.result(timeout=30)
        else:
            return loop.run_until_complete(
                generate_and_save_report(result, agent, config, start_time)
            )
    except Exception as e:
        logger.error(f"Sync report generation failed: {e}")
        return None
