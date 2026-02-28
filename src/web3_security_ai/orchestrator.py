#!/usr/bin/env python3

"""
Orchestrator Agent for the Web3 Security Audit System.

DEPRECATED: Use cai.web3.pipeline.EliteWeb3Pipeline for all audit workflows.
This module is retained for backward compatibility only.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

from .base_agent import BaseAgent, AgentConfig, AgentType, AgentRole


class WorkflowState(Enum):
    """State of the audit workflow."""
    INITIALIZING = "initializing"
    ANALYZING = "analyzing"
    PROCESSING = "processing"
    EVALUATING = "evaluating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    """Represents a task in the workflow."""
    id: str
    name: str
    description: str
    agent_type: AgentType
    priority: int = 1
    status: str = "pending"
    result: Optional[Any] = None
    dependencies: List[str] = None


class OrchestratorAgent(BaseAgent):
    """Main orchestrator agent that coordinates all security audit agents."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.agents: Dict[str, BaseAgent] = {}
        self.logger = logging.getLogger(__name__)
        
    async def initialize(self) -> bool:
        """Initialize the orchestrator agent."""
        self.is_active = True
        self.logger.info(f"Orchestrator {self.name} initialized")
        return True
    
    async def cleanup(self) -> None:
        """Clean up the orchestrator agent."""
        self.is_active = False
        self.logger.info(f"Orchestrator {self.name} cleaned up")
    
    async def register_agent(self, agent: BaseAgent) -> None:
        """Register a subordinate agent with the orchestrator."""
        self.agents[agent.name] = agent
        self.logger.info(f"Registered agent: {agent.name}")
    
    async def execute_task(self, task: str, **kwargs) -> Dict[str, Any]:
        """Deprecated task-based orchestration."""
        self.logger.warning("execute_task is deprecated in OrchestratorAgent. Use EliteWeb3Pipeline.")
        return {"success": False, "error": "Deprecated. Use EliteWeb3Pipeline."}
    
    async def _execute_workflow_step(self, task: Task, **kwargs) -> Any:
        """Execute a specific workflow step using appropriate agents.
        
        Args:
            task: Task to execute
            **kwargs: Additional parameters
            
        Returns:
            Execution result
        """
        # Find appropriate agent for this task type
        agent = self._get_agent_by_type(task.agent_type)
        if not agent:
            raise ValueError(f"No agent found for type: {task.agent_type}")
        
        # Execute using the appropriate agent
        return await agent.execute_task(task.description, **kwargs)
    
    def _get_agent_by_type(self, agent_type: AgentType) -> Optional[BaseAgent]:
        """Get agent by type from registered agents.
        
        Args:
            agent_type: Type of agent to find
            
        Returns:
            Agent instance or None
        """
        for agent in self.agents.values():
            if agent.agent_type == agent_type:
                return agent
        return None
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """Deprecated."""
        return {"status": "deprecated"}
    
    def get_agent_summary(self) -> Dict[str, Any]:
        """Get summary of all registered agents.
        
        Returns:
            Dictionary with agent summary
        """
        return {
            agent.name: {
                "type": agent.agent_type.value,
                "role": agent.role.value,
                "capabilities": agent.capabilities,
                "active": agent.is_active
            }
            for agent in self.agents.values()
        }
