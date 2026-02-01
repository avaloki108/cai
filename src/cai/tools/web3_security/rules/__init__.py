"""
Centralized Rule Configuration System for Web3 Security Analysis

This module provides a YAML-based rule management system that centralizes
vulnerability detection rules, false positive patterns, and tool weights.

Benefits:
- Easy rule updates without code changes
- Versioned rules for reproducibility
- Clear documentation of detection logic
- Tool-specific reliability weights
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass
class VulnerabilityRule:
    """Represents a single vulnerability detection rule."""
    
    name: str
    version: str
    category: str
    severity: str
    confidence: str
    description: str
    
    false_positive_conditions: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    required_patterns: Dict[str, Any] = field(default_factory=dict)
    tool_weights: Dict[str, float] = field(default_factory=dict)
    
    examples: List[Dict[str, str]] = field(default_factory=list)
    impact: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerabilityRule':
        """Create a VulnerabilityRule from a dictionary."""
        return cls(
            name=data.get('name', ''),
            version=data.get('version', '1.0'),
            category=data.get('category', ''),
            severity=data.get('severity', 'medium'),
            confidence=data.get('confidence', 'medium'),
            description=data.get('description', ''),
            false_positive_conditions=data.get('false_positive_conditions', []),
            detection_patterns=data.get('detection_patterns', []),
            required_patterns=data.get('required_patterns', {}),
            tool_weights=data.get('tool_weights', {}),
            examples=data.get('examples', []),
            impact=data.get('impact', []),
            remediation=data.get('remediation', []),
            references=data.get('references', [])
        )
    
    def get_tool_weight(self, tool: str) -> float:
        """Get the weight/reliability for a specific tool."""
        return self.tool_weights.get(tool.lower(), 0.5)  # Default 0.5
    
    def is_false_positive(self, code_context: str) -> bool:
        """
        Check if code context matches false positive conditions.
        
        Args:
            code_context: Source code snippet to analyze
            
        Returns:
            True if matches FP conditions
        """
        code_lower = code_context.lower()
        matches = 0
        
        for condition in self.false_positive_conditions:
            condition_check = condition.lower().replace('_', ' ')
            
            # Map conditions to code patterns
            if condition == 'view_function' and 'view' in code_lower:
                matches += 1
            elif condition == 'pure_function' and 'pure' in code_lower:
                matches += 1
            elif condition == 'nonReentrant_modifier' and 'nonreentrant' in code_lower:
                matches += 1
            elif condition == 'onlyOwner_modifier' and 'onlyowner' in code_lower:
                matches += 1
            elif condition == 'require_msg_sender_check' and 'require(msg.sender' in code_lower:
                matches += 1
            elif condition.replace('_', '') in code_lower.replace(' ', ''):
                matches += 1
        
        # If 2+ FP conditions match, likely false positive
        return matches >= 2
    
    def calculate_adjusted_confidence(
        self,
        base_confidence: float,
        tool: str,
        code_context: str = ""
    ) -> float:
        """
        Calculate adjusted confidence based on tool weight and FP patterns.
        
        Args:
            base_confidence: Initial confidence from tool
            tool: Tool that generated the finding
            code_context: Source code for FP checking
            
        Returns:
            Adjusted confidence (0.0 - 1.0)
        """
        # Apply tool-specific weight
        tool_weight = self.get_tool_weight(tool)
        confidence = base_confidence * tool_weight
        
        # Reduce if false positive indicators present
        if code_context and self.is_false_positive(code_context):
            confidence *= 0.5  # 50% reduction for FP indicators
        
        return min(confidence, 1.0)


class RuleManager:
    """Manages loading and accessing vulnerability detection rules."""
    
    def __init__(self, rules_dir: Optional[Path] = None):
        """
        Initialize the rule manager.
        
        Args:
            rules_dir: Directory containing YAML rule files.
                      Defaults to this package's rules directory.
        """
        if rules_dir is None:
            rules_dir = Path(__file__).parent
        
        self.rules_dir = Path(rules_dir)
        self._rules: Dict[str, VulnerabilityRule] = {}
        self._loaded = False
    
    def load_rules(self, force_reload: bool = False) -> Dict[str, VulnerabilityRule]:
        """
        Load all YAML rule files from the rules directory.
        
        Args:
            force_reload: If True, reload even if already loaded
            
        Returns:
            Dictionary mapping rule names to VulnerabilityRule objects
        """
        if self._loaded and not force_reload:
            return self._rules
        
        self._rules.clear()
        
        # Find all YAML files in rules directory
        yaml_files = list(self.rules_dir.glob('*.yml')) + list(self.rules_dir.glob('*.yaml'))
        
        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    
                    if rule_data and isinstance(rule_data, dict):
                        rule = VulnerabilityRule.from_dict(rule_data)
                        
                        # Use category as key (or name if no category)
                        key = rule.category or rule.name
                        self._rules[key] = rule
                        
            except Exception as e:
                # Log error but continue loading other rules
                import sys
                print(f"Error loading rule from {yaml_file}: {e}", file=sys.stderr)
                continue
        
        self._loaded = True
        return self._rules
    
    def get_rule(self, rule_name: str) -> Optional[VulnerabilityRule]:
        """
        Get a specific rule by name or category.
        
        Args:
            rule_name: Name or category of the rule
            
        Returns:
            VulnerabilityRule if found, None otherwise
        """
        if not self._loaded:
            self.load_rules()
        
        return self._rules.get(rule_name)
    
    def get_rule_for_finding_type(self, finding_type: str) -> Optional[VulnerabilityRule]:
        """
        Get the appropriate rule for a finding type.
        
        Handles normalization of finding types from different tools.
        
        Args:
            finding_type: Type of vulnerability finding
            
        Returns:
            Best matching VulnerabilityRule or None
        """
        if not self._loaded:
            self.load_rules()
        
        finding_lower = finding_type.lower().replace('-', '_').replace(' ', '_')
        
        # Direct match
        if finding_lower in self._rules:
            return self._rules[finding_lower]
        
        # Partial match
        for rule_key, rule in self._rules.items():
            if rule_key in finding_lower or finding_lower in rule_key:
                return rule
            
            # Check if finding_type matches any detection patterns
            for pattern in rule.detection_patterns:
                if pattern.replace('_', '') in finding_lower.replace('_', ''):
                    return rule
        
        return None
    
    def list_rules(self) -> List[str]:
        """Get list of all available rule names."""
        if not self._loaded:
            self.load_rules()
        
        return list(self._rules.keys())
    
    def get_all_rules(self) -> Dict[str, VulnerabilityRule]:
        """Get all loaded rules."""
        if not self._loaded:
            self.load_rules()
        
        return self._rules.copy()


# Global rule manager instance
_global_rule_manager: Optional[RuleManager] = None


@lru_cache(maxsize=1)
def get_rule_manager() -> RuleManager:
    """
    Get the global RuleManager instance.
    
    Returns:
        Singleton RuleManager instance
    """
    global _global_rule_manager
    
    if _global_rule_manager is None:
        _global_rule_manager = RuleManager()
        _global_rule_manager.load_rules()
    
    return _global_rule_manager


def get_rule(rule_name: str) -> Optional[VulnerabilityRule]:
    """
    Convenience function to get a rule from the global manager.
    
    Args:
        rule_name: Name or category of the rule
        
    Returns:
        VulnerabilityRule if found, None otherwise
    """
    return get_rule_manager().get_rule(rule_name)


def get_rule_for_finding(finding_type: str) -> Optional[VulnerabilityRule]:
    """
    Convenience function to get the appropriate rule for a finding type.
    
    Args:
        finding_type: Type of vulnerability finding
        
    Returns:
        Best matching VulnerabilityRule or None
    """
    return get_rule_manager().get_rule_for_finding_type(finding_type)


__all__ = [
    'VulnerabilityRule',
    'RuleManager',
    'get_rule_manager',
    'get_rule',
    'get_rule_for_finding',
]
