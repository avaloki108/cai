"""
HMAW - Hierarchical Multi-Agent Workflow Pattern.

From the research paper: "Towards Hierarchical Multi-Agent Workflows 
for Zero-Shot Prompt Optimization"

Key insights:
- CEO → Manager → Worker hierarchy for decomposing tasks
- Skip connections: Original query passed directly to all layers
- 30.7% improvement over baseline using this structure
- Three-layer structure is optimal (more layers = diminishing returns)

Architecture:
    ┌─────────────────────────────────────────────────────┐
    │                    CEO (Orchestrator)                │
    │  - High-level audit plan + constraints               │
    │  - Original query passed to all layers (skip conn)   │
    └─────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │ Vuln    │    │ Economic│    │ Access  │  ← Managers
    │ Manager │    │ Manager │    │ Manager │
    └────┬────┘    └────┬────┘    └────┬────┘
         ▼              ▼              ▼
      Workers        Workers        Workers

Skip Connection Principle:
    - CEO receives: original_query
    - Managers receive: original_query + ceo_guidelines
    - Workers receive: original_query + ceo_guidelines + manager_instructions
    
This ensures context is not lost through hierarchical summarization.
"""

from typing import Dict, Any, Optional, List, Union, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
import asyncio

from cai.agents.patterns.pattern import Pattern, PatternType

if TYPE_CHECKING:
    from cai.sdk.agents import Agent


class HierarchyLevel(Enum):
    """Levels in the HMAW hierarchy."""
    CEO = "ceo"
    MANAGER = "manager"
    WORKER = "worker"


@dataclass
class HierarchyNode:
    """A node in the HMAW hierarchy."""
    
    agent: Any
    level: HierarchyLevel
    domain: str  # e.g., "vulnerability", "economic", "access_control"
    children: List['HierarchyNode'] = field(default_factory=list)
    parent: Optional['HierarchyNode'] = None
    
    def __post_init__(self):
        # Link children to parent
        for child in self.children:
            child.parent = self
    
    def add_child(self, child: 'HierarchyNode') -> 'HierarchyNode':
        """Add a child node."""
        child.parent = self
        self.children.append(child)
        return self
    
    @property
    def agent_name(self) -> str:
        return getattr(self.agent, 'name', str(self.agent))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "level": self.level.value,
            "domain": self.domain,
            "children": [c.to_dict() for c in self.children]
        }


@dataclass
class SkipConnection:
    """
    Skip connection for passing context directly through hierarchy.
    
    Ensures original query reaches all layers without information loss.
    """
    
    original_query: str
    ceo_guidelines: Optional[str] = None
    manager_instructions: Dict[str, str] = field(default_factory=dict)
    
    def get_context_for_level(
        self, 
        level: HierarchyLevel,
        domain: Optional[str] = None
    ) -> str:
        """Get accumulated context for a specific level."""
        
        if level == HierarchyLevel.CEO:
            return self.original_query
        
        elif level == HierarchyLevel.MANAGER:
            parts = [self.original_query]
            if self.ceo_guidelines:
                parts.append(f"\n## CEO Guidelines\n{self.ceo_guidelines}")
            return "\n".join(parts)
        
        elif level == HierarchyLevel.WORKER:
            parts = [self.original_query]
            if self.ceo_guidelines:
                parts.append(f"\n## CEO Guidelines\n{self.ceo_guidelines}")
            if domain and domain in self.manager_instructions:
                parts.append(f"\n## Manager Instructions ({domain})\n{self.manager_instructions[domain]}")
            return "\n".join(parts)
        
        return self.original_query
    
    def set_ceo_output(self, guidelines: str) -> None:
        """Set CEO guidelines after CEO execution."""
        self.ceo_guidelines = guidelines
    
    def set_manager_output(self, domain: str, instructions: str) -> None:
        """Set manager instructions for a domain."""
        self.manager_instructions[domain] = instructions


@dataclass
class HMAWPattern(Pattern):
    """
    Hierarchical Multi-Agent Workflow Pattern.
    
    Implements the CEO → Manager → Worker hierarchy with skip connections
    from the HMAW research paper.
    
    Attributes:
        ceo: The CEO/orchestrator agent at the top
        managers: Dict mapping domain names to manager agents
        workers: Dict mapping domain names to lists of worker agents
        skip_connections: Whether to use skip connections (recommended)
        parallel_managers: Whether to run managers in parallel
        parallel_workers: Whether to run workers within a domain in parallel
    """
    
    ceo: Optional[Any] = None
    managers: Dict[str, Any] = field(default_factory=dict)
    workers: Dict[str, List[Any]] = field(default_factory=dict)
    
    # HMAW configuration
    skip_connections: bool = True  # Critical for performance
    parallel_managers: bool = True
    parallel_workers: bool = True
    
    # Execution state
    _hierarchy: Optional[HierarchyNode] = field(default=None, repr=False)
    _skip_context: Optional[SkipConnection] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Initialize as hierarchical pattern type."""
        self.type = PatternType.HMAW
        super().__post_init__()
    
    def set_ceo(self, agent: Any) -> 'HMAWPattern':
        """Set the CEO agent."""
        self.ceo = agent
        self.root_agent = agent
        if agent not in self.agents:
            self.agents.append(agent)
        return self
    
    def add_manager(self, domain: str, agent: Any) -> 'HMAWPattern':
        """Add a manager for a specific domain."""
        self.managers[domain] = agent
        if agent not in self.agents:
            self.agents.append(agent)
        return self
    
    def add_worker(self, domain: str, agent: Any) -> 'HMAWPattern':
        """Add a worker to a domain."""
        if domain not in self.workers:
            self.workers[domain] = []
        self.workers[domain].append(agent)
        if agent not in self.agents:
            self.agents.append(agent)
        return self
    
    def build_hierarchy(self) -> HierarchyNode:
        """Build the hierarchy tree from configured agents."""
        if not self.ceo:
            raise ValueError("CEO agent must be set")
        
        # Create CEO node
        ceo_node = HierarchyNode(
            agent=self.ceo,
            level=HierarchyLevel.CEO,
            domain="orchestration"
        )
        
        # Create manager nodes
        for domain, manager in self.managers.items():
            manager_node = HierarchyNode(
                agent=manager,
                level=HierarchyLevel.MANAGER,
                domain=domain
            )
            
            # Create worker nodes for this domain
            if domain in self.workers:
                for worker in self.workers[domain]:
                    worker_node = HierarchyNode(
                        agent=worker,
                        level=HierarchyLevel.WORKER,
                        domain=domain
                    )
                    manager_node.add_child(worker_node)
            
            ceo_node.add_child(manager_node)
        
        self._hierarchy = ceo_node
        return ceo_node
    
    async def execute(
        self, 
        query: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the HMAW pattern.
        
        Args:
            query: The original audit query/target
            context: Additional context
            
        Returns:
            Aggregated results from all hierarchy levels
        """
        # Build hierarchy if not already built
        if not self._hierarchy:
            self.build_hierarchy()
        
        # Initialize skip connection context
        self._skip_context = SkipConnection(original_query=query)
        
        results = {
            "ceo": None,
            "managers": {},
            "workers": {},
            "aggregated": None
        }
        
        # Phase 1: CEO establishes guidelines
        ceo_result = await self._execute_ceo(query, context)
        results["ceo"] = ceo_result
        
        # Update skip connection with CEO output
        if self.skip_connections and ceo_result:
            self._skip_context.set_ceo_output(
                ceo_result.get("guidelines", str(ceo_result))
            )
        
        # Phase 2: Managers execute with skip connection context
        manager_results = await self._execute_managers(context)
        results["managers"] = manager_results
        
        # Phase 3: Workers execute with full skip connection context
        worker_results = await self._execute_workers(context)
        results["workers"] = worker_results
        
        # Phase 4: Aggregate results back up the hierarchy
        results["aggregated"] = await self._aggregate_results(results)
        
        return results
    
    async def _execute_ceo(
        self, 
        query: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute the CEO agent."""
        if not self.ceo:
            return {}
        
        # CEO receives original query only
        ceo_context = self._skip_context.get_context_for_level(HierarchyLevel.CEO)
        
        # In real implementation, call: await self.ceo.run(ceo_context, context)
        return {
            "agent": getattr(self.ceo, 'name', str(self.ceo)),
            "level": "ceo",
            "input": ceo_context,
            "guidelines": "Placeholder CEO guidelines"
        }
    
    async def _execute_managers(
        self, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute all manager agents."""
        if not self.managers:
            return {}
        
        if self.parallel_managers:
            # Run managers in parallel
            tasks = {
                domain: self._execute_single_manager(domain, manager, context)
                for domain, manager in self.managers.items()
            }
            
            results = {}
            for domain, task in tasks.items():
                try:
                    results[domain] = await task
                    
                    # Update skip connection with manager output
                    if self.skip_connections:
                        self._skip_context.set_manager_output(
                            domain,
                            results[domain].get("instructions", str(results[domain]))
                        )
                except Exception as e:
                    results[domain] = {"error": str(e)}
            
            return results
        else:
            # Run managers sequentially
            results = {}
            for domain, manager in self.managers.items():
                results[domain] = await self._execute_single_manager(
                    domain, manager, context
                )
                if self.skip_connections:
                    self._skip_context.set_manager_output(
                        domain,
                        results[domain].get("instructions", str(results[domain]))
                    )
            return results
    
    async def _execute_single_manager(
        self,
        domain: str,
        manager: Any,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a single manager agent."""
        # Manager receives original query + CEO guidelines (skip connection)
        manager_context = self._skip_context.get_context_for_level(
            HierarchyLevel.MANAGER, domain
        )
        
        # In real implementation, call: await manager.run(manager_context, context)
        return {
            "agent": getattr(manager, 'name', str(manager)),
            "level": "manager",
            "domain": domain,
            "input": manager_context,
            "instructions": f"Placeholder {domain} manager instructions"
        }
    
    async def _execute_workers(
        self, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Execute all worker agents."""
        if not self.workers:
            return {}
        
        results = {}
        
        for domain, workers in self.workers.items():
            if self.parallel_workers:
                # Run workers in parallel within domain
                tasks = [
                    self._execute_single_worker(domain, worker, context)
                    for worker in workers
                ]
                results[domain] = await asyncio.gather(*tasks, return_exceptions=True)
                results[domain] = [
                    r if not isinstance(r, Exception) else {"error": str(r)}
                    for r in results[domain]
                ]
            else:
                # Run workers sequentially
                results[domain] = []
                for worker in workers:
                    result = await self._execute_single_worker(domain, worker, context)
                    results[domain].append(result)
        
        return results
    
    async def _execute_single_worker(
        self,
        domain: str,
        worker: Any,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a single worker agent."""
        # Worker receives full skip connection context
        worker_context = self._skip_context.get_context_for_level(
            HierarchyLevel.WORKER, domain
        )
        
        # In real implementation: await worker.run(worker_context, context)
        return {
            "agent": getattr(worker, 'name', str(worker)),
            "level": "worker",
            "domain": domain,
            "input": worker_context,
            "findings": []
        }
    
    async def _aggregate_results(
        self, 
        results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Aggregate results from all levels."""
        all_findings = []
        
        # Collect worker findings
        for domain, worker_results in results.get("workers", {}).items():
            for worker_result in worker_results:
                if isinstance(worker_result, dict):
                    findings = worker_result.get("findings", [])
                    for finding in findings:
                        finding["domain"] = domain
                        all_findings.append(finding)
        
        return {
            "total_findings": len(all_findings),
            "by_domain": {
                domain: len([f for f in all_findings if f.get("domain") == domain])
                for domain in self.workers.keys()
            },
            "findings": all_findings
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary."""
        base = super().to_dict()
        base.update({
            "ceo": getattr(self.ceo, "name", str(self.ceo)) if self.ceo else None,
            "managers": {
                domain: getattr(m, "name", str(m))
                for domain, m in self.managers.items()
            },
            "workers": {
                domain: [getattr(w, "name", str(w)) for w in workers]
                for domain, workers in self.workers.items()
            },
            "skip_connections": self.skip_connections,
            "parallel_managers": self.parallel_managers,
            "parallel_workers": self.parallel_workers,
        })
        
        if self._hierarchy:
            base["hierarchy"] = self._hierarchy.to_dict()
        
        return base
    
    def validate(self) -> bool:
        """Validate pattern configuration."""
        return self.ceo is not None


def hmaw_pattern(
    name: str,
    ceo: Any,
    managers: Dict[str, Any],
    workers: Optional[Dict[str, List[Any]]] = None,
    description: str = "HMAW CEO → Manager → Worker hierarchy",
    **kwargs
) -> HMAWPattern:
    """
    Factory function for creating HMAW patterns.
    
    Args:
        name: Pattern identifier
        ceo: The CEO/orchestrator agent
        managers: Dict mapping domain names to manager agents
        workers: Dict mapping domain names to lists of worker agents
        description: Human-readable description
        **kwargs: Additional pattern options
        
    Returns:
        Configured HMAWPattern
    """
    pattern = HMAWPattern(
        name=name,
        type=PatternType.HMAW,
        description=description,
        **kwargs
    )
    
    pattern.set_ceo(ceo)
    
    for domain, manager in managers.items():
        pattern.add_manager(domain, manager)
    
    if workers:
        for domain, worker_list in workers.items():
            for worker in worker_list:
                pattern.add_worker(domain, worker)
    
    return pattern


__all__ = [
    'HierarchyLevel',
    'HierarchyNode',
    'SkipConnection',
    'HMAWPattern',
    'hmaw_pattern',
]
