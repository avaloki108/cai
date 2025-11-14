#!/usr/bin/env python3

"""
Base agent class for the Web3 Security Audit System.
Defines the common interface and structure for all security agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from enum import Enum
import asyncio
import logging


class AgentType(Enum):
    """Types of agents in the system."""
    ORCHESTRATOR = "orchestrator"
    WEB3_AUDIT = "web3_audit"
    AI_ML = "ai_ml"
    TRADITIONAL_SECURITY = "traditional_security"
    STATIC_ANALYSIS = "static_analysis"
    REPORTING = "reporting"


class AgentRole(Enum):
    """Roles that agents can play."""
    ANALYST = "analyst"
    EXECUTOR = "executor"
    EVALUATOR = "evaluator"
    COORDINATOR = "coordinator"
    REPORTER = "reporter"


class AgentConfig:
    """Configuration for an agent."""
    def __init__(self, name: str, agent_type: AgentType, role: AgentRole, 
                 capabilities: List[str], max_concurrent_tasks: int = 1):
        self.name = name
        self.agent_type = agent_type
        self.role = role
        self.capabilities = capabilities
        self.max_concurrent_tasks = max_concurrent_tasks


class BaseAgent(ABC):
    """Abstract base class for all security agents."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.name = config.name
        self.agent_type = config.agent_type
        self.role = config.role
        self.capabilities = config.capabilities
        self.is_active = False
        self.logger = logging.getLogger(f"{self.__class__.__name__}.{self.name}")
        self.concurrency_semaphore = asyncio.Semaphore(config.max_concurrent_tasks)
        
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the agent.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up the agent resources."""
        pass
    
    @abstractmethod
    async def execute_task(self, task: str, **kwargs) -> Dict[str, Any]:
        """Execute a task assigned to this agent.
        
        Args:
            task: Task description or data
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with execution results
        """
        pass
    
    async def execute_with_concurrency_limit(self, task: str, **kwargs) -> Dict[str, Any]:
        """Execute task with concurrency limiting.
        
        Args:
            task: Task description or data
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with execution results
        """
        async with self.concurrency_semaphore:
            return await self.execute_task(task, **kwargs)
