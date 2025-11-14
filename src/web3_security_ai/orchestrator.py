#!/usr/bin/env python3

"""
Orchestrator Agent for the Web3 Security Audit System.
This agent coordinates all other agents and manages the audit workflow.
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


class WorkflowManager:
    """Manages the overall workflow execution."""
    
    def __init__(self):
        self.state = WorkflowState.INITIALIZING
        self.tasks: List[Task] = []
        self.current_task_index = 0
        self.results: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
    
    def add_task(self, task: Task) -> None:
        """Add a task to the workflow."""
        self.tasks.append(task)
    
    def get_next_task(self) -> Optional[Task]:
        """Get the next task that should be executed."""
        for task in self.tasks[self.current_task_index:]:
            if task.status == "pending":
                return task
        return None
    
    def update_task_status(self, task_id: str, status: str, result: Any = None) -> None:
        """Update the status of a task."""
        for task in self.tasks:
            if task.id == task_id:
                task.status = status
                task.result = result
                if status == "completed":
                    self.current_task_index += 1
                break


class OrchestratorAgent(BaseAgent):
    """Main orchestrator agent that coordinates all security audit agents."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.workflow_manager = WorkflowManager()
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
        """Execute a workflow task.
        
        Args:
            task: Description of task to execute
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with execution results
        """
        try:
            # Parse the task
            task_data = json.loads(task) if isinstance(task, str) else task
            
            # Create task object
            workflow_task = Task(
                id=task_data.get("id", f"task_{len(self.workflow_manager.tasks)}"),
                name=task_data.get("name", "Unnamed Task"),
                description=task_data.get("description", ""),
                agent_type=AgentType(task_data.get("agent_type", "web3_audit")),
                priority=task_data.get("priority", 1)
            )
            
            # Add task to workflow
            self.workflow_manager.add_task(workflow_task)
            
            # Execute the task
            result = await self._execute_workflow_step(workflow_task, **kwargs)
            
            # Update task status
            self.workflow_manager.update_task_status(workflow_task.id, "completed", result)
            
            return {
                "success": True,
                "task_id": workflow_task.id,
                "result": result,
                "message": f"Task {workflow_task.name} completed successfully"
            }
            
        except Exception as e:
            self.logger.error(f"Error executing task: {str(e)}")
            self.workflow_manager.update_task_status(workflow_task.id, "failed")
            return {
                "success": False,
                "error": str(e),
                "message": f"Task failed: {str(e)}"
            }
    
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
        """Get current workflow status.
        
        Returns:
            Dictionary with workflow status information
        """
        return {
            "state": self.workflow_manager.state.value,
            "tasks": [
                {
                    "id": t.id,
                    "name": t.name,
                    "status": t.status,
                    "agent_type": t.agent_type.value
                }
                for t in self.workflow_manager.tasks
            ],
            "current_task_index": self.workflow_manager.current_task_index,
            "total_tasks": len(self.workflow_manager.tasks)
        }
    
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
