"""
Path Constraint Extraction and Analysis

This module extracts and analyzes path constraints from symbolic
execution tools (Mythril, Oyente) to enable deeper vulnerability
validation and symbolic-static correlation.
"""

import json
import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PathConstraint:
    """Represents a path constraint from symbolic execution."""
    
    source_tool: str  # "mythril" or "oyente"
    constraint_smt: str  # SMT formula
    constraint_type: str  # "branch", "assert", "require", etc.
    
    # Location information
    contract: str
    function: str
    pc: Optional[int] = None  # Program counter
    line: Optional[int] = None
    
    # State information
    affected_state_vars: List[str] = field(default_factory=list)
    involved_variables: Set[str] = field(default_factory=set)
    
    # Analysis metadata
    feasibility_score: float = 1.0  # 0-1, based on SMT solver
    complexity: int = 0  # Number of variables/operators
    
    # Connection to findings
    related_finding_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "constraint_smt": self.constraint_smt,
            "constraint_type": self.constraint_type,
            "location": {
                "contract": self.contract,
                "function": self.function,
                "pc": self.pc,
                "line": self.line
            },
            "state_vars": self.affected_state_vars,
            "variables": list(self.involved_variables),
            "feasibility": self.feasibility_score,
            "complexity": self.complexity
        }


class MythrilConstraintExtractor:
    """Extract path constraints from Mythril JSON output."""
    
    @staticmethod
    def extract(mythril_json: Dict[str, Any]) -> List[PathConstraint]:
        """
        Extract constraints from Mythril analysis results.
        
        Args:
            mythril_json: Mythril output as dictionary
            
        Returns:
            List of PathConstraint objects
        """
        constraints = []
        
        # Mythril JSON structure: {"success": true, "issues": [...]}
        issues = mythril_json.get("issues", [])
        
        for issue in issues:
            # Extract basic info
            contract = issue.get("contract", "unknown")
            function = issue.get("function", "unknown")
            swc_id = issue.get("swcID", "")
            
            # Try to extract constraints from transaction sequence
            tx_sequence = issue.get("extra", {}).get("testcase", {}).get("steps", [])
            
            for step in tx_sequence:
                # Look for constraints in call arguments or conditions
                if "arguments" in step:
                    constraint = PathConstraint(
                        source_tool="mythril",
                        constraint_smt=str(step.get("arguments", {})),
                        constraint_type="call_argument",
                        contract=contract,
                        function=function
                    )
                    constraints.append(constraint)
            
            # Extract from source map if available
            source_map = issue.get("sourceMap", "")
            if source_map:
                # Parse source map for PC and line info
                match = re.search(r"(\d+):(\d+):(\d+)", source_map)
                if match:
                    pc = int(match.group(1))
                    length = int(match.group(2))
                    file_idx = int(match.group(3))
                    
                    constraint = PathConstraint(
                        source_tool="mythril",
                        constraint_smt=f"PC={pc}",
                        constraint_type="vulnerability_location",
                        contract=contract,
                        function=function,
                        pc=pc
                    )
                    constraints.append(constraint)
        
        return constraints


class OyenteConstraintExtractor:
    """Extract path constraints from Oyente output."""
    
    @staticmethod
    def extract(oyente_json: Dict[str, Any]) -> List[PathConstraint]:
        """
        Extract constraints from Oyente analysis results.
        
        Args:
            oyente_json: Oyente output as dictionary
            
        Returns:
            List of PathConstraint objects
        """
        constraints = []
        
        # Oyente structure varies, look for paths
        for contract_name, contract_data in oyente_json.items():
            if isinstance(contract_data, dict):
                # Look for execution paths
                paths = contract_data.get("paths", [])
                
                for path in paths:
                    if isinstance(path, dict):
                        # Extract path conditions
                        conditions = path.get("conditions", [])
                        
                        for cond in conditions:
                            constraint = PathConstraint(
                                source_tool="oyente",
                                constraint_smt=str(cond),
                                constraint_type="path_condition",
                                contract=contract_name,
                                function=path.get("function", "unknown")
                            )
                            constraints.append(constraint)
        
        return constraints


class ConstraintDatabase:
    """
    Storage and retrieval system for path constraints.
    
    Enables querying constraints by contract, function, or vulnerability type.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the constraint database.
        
        Args:
            db_path: Path to JSON file for persistent storage
        """
        if db_path is None:
            db_path = str(Path.home() / ".cai" / "constraints.json")
        
        self.db_path = Path(db_path)
        self.constraints: List[PathConstraint] = []
        
        # Load existing database
        if self.db_path.exists():
            self.load()
    
    def add(self, constraint: PathConstraint):
        """Add a constraint to the database."""
        self.constraints.append(constraint)
    
    def add_batch(self, constraints: List[PathConstraint]):
        """Add multiple constraints."""
        self.constraints.extend(constraints)
    
    def query_by_contract(self, contract: str) -> List[PathConstraint]:
        """Get all constraints for a specific contract."""
        return [c for c in self.constraints if c.contract == contract]
    
    def query_by_function(self, function: str) -> List[PathConstraint]:
        """Get all constraints for a specific function."""
        return [c for c in self.constraints if c.function == function]
    
    def query_by_location(self, contract: str, function: str) -> List[PathConstraint]:
        """Get constraints for a specific contract function."""
        return [
            c for c in self.constraints
            if c.contract == contract and c.function == function
        ]
    
    def query_feasible(self, threshold: float = 0.7) -> List[PathConstraint]:
        """Get constraints with feasibility above threshold."""
        return [c for c in self.constraints if c.feasibility_score >= threshold]
    
    def save(self):
        """Save database to JSON file."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "version": "1.0",
            "constraints": [c.to_dict() for c in self.constraints]
        }
        
        with open(self.db_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self):
        """Load database from JSON file."""
        if not self.db_path.exists():
            return
        
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        
        # Reconstruct constraints
        self.constraints = []
        for c_dict in data.get("constraints", []):
            loc = c_dict.get("location", {})
            constraint = PathConstraint(
                source_tool=c_dict["source_tool"],
                constraint_smt=c_dict["constraint_smt"],
                constraint_type=c_dict["constraint_type"],
                contract=loc.get("contract", "unknown"),
                function=loc.get("function", "unknown"),
                pc=loc.get("pc"),
                line=loc.get("line"),
                affected_state_vars=c_dict.get("state_vars", []),
                involved_variables=set(c_dict.get("variables", [])),
                feasibility_score=c_dict.get("feasibility", 1.0),
                complexity=c_dict.get("complexity", 0)
            )
            self.constraints.append(constraint)
    
    def clear(self):
        """Clear all constraints."""
        self.constraints = []


def extract_constraints_from_mythril(
    mythril_output: Dict[str, Any]
) -> List[PathConstraint]:
    """
    Convenience function to extract constraints from Mythril output.
    
    Args:
        mythril_output: Mythril JSON output
        
    Returns:
        List of extracted PathConstraint objects
    """
    extractor = MythrilConstraintExtractor()
    return extractor.extract(mythril_output)


def extract_constraints_from_oyente(
    oyente_output: Dict[str, Any]
) -> List[PathConstraint]:
    """
    Convenience function to extract constraints from Oyente output.
    
    Args:
        oyente_output: Oyente JSON output
        
    Returns:
        List of extracted PathConstraint objects
    """
    extractor = OyenteConstraintExtractor()
    return extractor.extract(oyente_output)


__all__ = [
    'PathConstraint',
    'MythrilConstraintExtractor',
    'OyenteConstraintExtractor',
    'ConstraintDatabase',
    'extract_constraints_from_mythril',
    'extract_constraints_from_oyente',
]
