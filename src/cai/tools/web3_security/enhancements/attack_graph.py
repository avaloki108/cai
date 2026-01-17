"""
Attack Graph Construction and Analysis Tool

This module builds attack graphs from vulnerability findings and analyzes
them to find viable exploit paths with game-theoretic payoff scoring.

Inspired by G-CTR (Generative Cut-the-Rope) from the CAI research paper.
"""

import json
import re
from typing import Any, Dict, List, Optional
from cai.sdk.agents import function_tool


# Vulnerability type to attack node mapping
VULN_TYPE_MAPPING = {
    # Access Control
    "unprotected-upgrade": {"category": "access_control", "entry_potential": True, "severity": 9},
    "suicidal": {"category": "access_control", "entry_potential": True, "severity": 10},
    "arbitrary-send": {"category": "access_control", "entry_potential": True, "severity": 9},
    "protected-vars": {"category": "access_control", "entry_potential": False, "severity": 7},
    "uninitialized-state": {"category": "access_control", "entry_potential": True, "severity": 8},
    
    # Reentrancy
    "reentrancy-eth": {"category": "reentrancy", "entry_potential": True, "severity": 9},
    "reentrancy-no-eth": {"category": "reentrancy", "entry_potential": True, "severity": 7},
    "reentrancy-benign": {"category": "reentrancy", "entry_potential": False, "severity": 3},
    "reentrancy-events": {"category": "reentrancy", "entry_potential": False, "severity": 4},
    
    # Oracle/Price
    "oracle-manipulation": {"category": "oracle", "entry_potential": True, "severity": 9},
    "price-manipulation": {"category": "oracle", "entry_potential": True, "severity": 9},
    "stale-price": {"category": "oracle", "entry_potential": True, "severity": 7},
    
    # Arithmetic
    "divide-before-multiply": {"category": "arithmetic", "entry_potential": False, "severity": 5},
    "integer-overflow": {"category": "arithmetic", "entry_potential": True, "severity": 8},
    "unchecked-transfer": {"category": "arithmetic", "entry_potential": True, "severity": 7},
    
    # External Calls
    "low-level-calls": {"category": "external_call", "entry_potential": True, "severity": 6},
    "unchecked-lowlevel": {"category": "external_call", "entry_potential": True, "severity": 7},
    "delegatecall-loop": {"category": "external_call", "entry_potential": True, "severity": 8},
    
    # Default
    "default": {"category": "other", "entry_potential": False, "severity": 5},
}


def _normalize_finding_type(finding_type: str) -> str:
    """Normalize finding type to a consistent format."""
    normalized = finding_type.lower().replace("_", "-").replace(" ", "-")
    return normalized


def _get_vuln_metadata(finding_type: str) -> Dict[str, Any]:
    """Get vulnerability metadata for a finding type."""
    normalized = _normalize_finding_type(finding_type)
    
    # Check for exact match
    if normalized in VULN_TYPE_MAPPING:
        return VULN_TYPE_MAPPING[normalized]
    
    # Check for partial matches
    for key, value in VULN_TYPE_MAPPING.items():
        if key in normalized or normalized in key:
            return value
    
    return VULN_TYPE_MAPPING["default"]


@function_tool
def build_attack_graph(findings: str, contract_code: str = "", ctf=None) -> str:
    """
    Build an attack graph from vulnerability findings.
    
    Constructs a directed graph where:
    - Nodes represent vulnerability instances or attack stages
    - Edges represent potential exploit chains (one vuln enabling another)
    - Each node has metadata for game-theoretic analysis
    
    Args:
        findings: JSON string of vulnerability findings from security tools.
                  Expected format: [{"type": "...", "severity": "...", "location": {...}, "description": "..."}]
        contract_code: Optional contract source code for enhanced analysis.
    
    Returns:
        JSON string representing the attack graph with nodes, edges, and metadata.
    
    Example:
        build_attack_graph('[{"type": "reentrancy-eth", "severity": "High", "location": {"contract": "Vault", "function": "withdraw"}}]')
    """
    try:
        # Parse findings
        if isinstance(findings, str):
            findings_list = json.loads(findings)
        else:
            findings_list = findings
        
        if not isinstance(findings_list, list):
            findings_list = [findings_list]
        
        # Build nodes from findings
        nodes = []
        node_id = 0
        
        for finding in findings_list:
            finding_type = finding.get("type", finding.get("check", "unknown"))
            vuln_meta = _get_vuln_metadata(finding_type)
            
            node = {
                "id": f"node_{node_id}",
                "type": finding_type,
                "category": vuln_meta["category"],
                "severity": finding.get("severity", vuln_meta["severity"]),
                "severity_numeric": vuln_meta["severity"],
                "entry_potential": vuln_meta["entry_potential"],
                "location": finding.get("location", {}),
                "contract": finding.get("location", {}).get("contract", 
                           finding.get("contract", "Unknown")),
                "function": finding.get("location", {}).get("function",
                           finding.get("function", "Unknown")),
                "description": finding.get("description", ""),
                "confidence": finding.get("confidence", 0.5),
                "raw_finding": finding,
            }
            nodes.append(node)
            node_id += 1
        
        # Build edges (potential exploit chains)
        edges = []
        for i, source in enumerate(nodes):
            for j, target in enumerate(nodes):
                if i == j:
                    continue
                
                # Define edge creation rules based on attack patterns
                should_create_edge = False
                edge_weight = 0.0
                
                # Access control issues can enable other attacks
                if source["category"] == "access_control" and source["entry_potential"]:
                    should_create_edge = True
                    edge_weight = 0.8
                
                # Reentrancy can chain with arithmetic issues
                if source["category"] == "reentrancy" and target["category"] == "arithmetic":
                    should_create_edge = True
                    edge_weight = 0.7
                
                # Oracle manipulation can enable economic exploits
                if source["category"] == "oracle":
                    should_create_edge = True
                    edge_weight = 0.9
                
                # External calls can enable reentrancy
                if source["category"] == "external_call" and target["category"] == "reentrancy":
                    should_create_edge = True
                    edge_weight = 0.85
                
                # Same contract vulnerabilities may chain
                if source["contract"] == target["contract"] and source["contract"] != "Unknown":
                    edge_weight = min(edge_weight + 0.1, 1.0) if should_create_edge else 0.5
                    should_create_edge = True
                
                if should_create_edge and edge_weight > 0.4:
                    edges.append({
                        "source": source["id"],
                        "target": target["id"],
                        "weight": edge_weight,
                        "chain_description": f"{source['type']} -> {target['type']}",
                    })
        
        # Calculate entry points (nodes that can start an attack)
        entry_points = [n["id"] for n in nodes if n["entry_potential"]]
        
        # Calculate target nodes (high severity, end of chains)
        target_nodes = [n["id"] for n in nodes if n["severity_numeric"] >= 8]
        
        # Build graph structure
        attack_graph = {
            "nodes": nodes,
            "edges": edges,
            "entry_points": entry_points,
            "target_nodes": target_nodes,
            "metadata": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "categories": list(set(n["category"] for n in nodes)),
                "max_severity": max((n["severity_numeric"] for n in nodes), default=0),
                "has_critical_path": len(entry_points) > 0 and len(target_nodes) > 0,
            }
        }
        
        return json.dumps(attack_graph, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to build attack graph: {str(e)}",
            "nodes": [],
            "edges": [],
        })


@function_tool
def find_exploit_paths(attack_graph: str, max_depth: int = 5, ctf=None) -> str:
    """
    Find viable exploit paths through the attack graph.
    
    Uses depth-first search to find paths from entry points to high-value targets,
    considering edge weights (attack chain viability) and node severities.
    
    Args:
        attack_graph: JSON string of attack graph from build_attack_graph().
        max_depth: Maximum chain length to consider (default: 5).
    
    Returns:
        JSON string with ranked exploit paths and their scores.
    
    Example:
        find_exploit_paths(attack_graph_json, max_depth=4)
    """
    try:
        if isinstance(attack_graph, str):
            graph = json.loads(attack_graph)
        else:
            graph = attack_graph
        
        nodes = {n["id"]: n for n in graph.get("nodes", [])}
        edges = graph.get("edges", [])
        entry_points = graph.get("entry_points", [])
        target_nodes = set(graph.get("target_nodes", []))
        
        # Build adjacency list
        adjacency = {}
        for edge in edges:
            source = edge["source"]
            if source not in adjacency:
                adjacency[source] = []
            adjacency[source].append({
                "target": edge["target"],
                "weight": edge["weight"],
            })
        
        # DFS to find paths
        all_paths = []
        
        def dfs(current: str, path: List[str], visited: set, cumulative_weight: float):
            if len(path) > max_depth:
                return
            
            # If we reached a target, record the path
            if current in target_nodes and len(path) > 1:
                path_nodes = [nodes[n] for n in path if n in nodes]
                all_paths.append({
                    "path": path.copy(),
                    "length": len(path),
                    "cumulative_weight": cumulative_weight,
                    "max_severity": max((n["severity_numeric"] for n in path_nodes), default=0),
                    "path_description": " -> ".join(
                        f"{nodes.get(n, {}).get('type', 'unknown')}" for n in path
                    ),
                })
            
            # Continue exploring
            for neighbor in adjacency.get(current, []):
                next_node = neighbor["target"]
                if next_node not in visited:
                    visited.add(next_node)
                    path.append(next_node)
                    dfs(next_node, path, visited, cumulative_weight * neighbor["weight"])
                    path.pop()
                    visited.remove(next_node)
        
        # Start DFS from each entry point
        for entry in entry_points:
            if entry in nodes:
                dfs(entry, [entry], {entry}, 1.0)
        
        # Score and rank paths
        for path in all_paths:
            # Score = severity * chain_weight / length
            path["exploit_score"] = (
                path["max_severity"] * path["cumulative_weight"] / path["length"]
            )
        
        # Sort by exploit score
        all_paths.sort(key=lambda p: p["exploit_score"], reverse=True)
        
        return json.dumps({
            "paths": all_paths[:20],  # Top 20 paths
            "total_paths_found": len(all_paths),
            "best_path": all_paths[0] if all_paths else None,
            "summary": {
                "entry_points_explored": len(entry_points),
                "paths_reaching_targets": len([p for p in all_paths if p["max_severity"] >= 8]),
            }
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to find exploit paths: {str(e)}",
            "paths": [],
        })


@function_tool
def score_path_payoff(exploit_path: str, gas_price_gwei: float = 30.0, eth_price_usd: float = 2000.0, ctf=None) -> str:
    """
    Calculate game-theoretic payoff score for an exploit path.
    
    Implements the scoring formula:
    Exploit_Score = (Severity × Likelihood × Payoff) / (Effort × Detection_Risk)
    
    Args:
        exploit_path: JSON string of exploit path from find_exploit_paths().
        gas_price_gwei: Current gas price in Gwei (for cost estimation).
        eth_price_usd: Current ETH price in USD.
    
    Returns:
        JSON string with detailed payoff analysis.
    
    Example:
        score_path_payoff(path_json, gas_price_gwei=50, eth_price_usd=3000)
    """
    try:
        if isinstance(exploit_path, str):
            path = json.loads(exploit_path)
        else:
            path = exploit_path
        
        # Extract path details
        path_length = path.get("length", 1)
        max_severity = path.get("max_severity", 5)
        cumulative_weight = path.get("cumulative_weight", 0.5)
        
        # Calculate component scores
        
        # Severity (1-10)
        severity_score = max_severity
        
        # Likelihood (0-1) - based on cumulative chain weight
        likelihood = cumulative_weight
        
        # Effort (1-10) - based on path length and complexity
        effort_base = min(path_length * 2, 10)
        
        # Detection risk (1-10) - longer paths are harder to hide
        detection_risk = min(path_length * 1.5 + 2, 10)
        
        # Estimated gas cost (in ETH)
        gas_per_step = 100000  # Approximate gas per exploit step
        total_gas = gas_per_step * path_length
        gas_cost_eth = (total_gas * gas_price_gwei) / 1e9
        gas_cost_usd = gas_cost_eth * eth_price_usd
        
        # Estimated payoff (simplified model based on severity)
        # Real payoff depends on protocol TVL, but we estimate based on severity
        payoff_multiplier = {
            10: 1000000,  # Critical - potential protocol drain
            9: 500000,    # High - significant fund loss
            8: 100000,    # Medium-High - partial drain
            7: 50000,     # Medium - limited loss
            6: 10000,     # Low-Medium
            5: 5000,      # Low
        }
        estimated_payoff_usd = payoff_multiplier.get(max_severity, 1000) * likelihood
        
        # Net payoff
        net_payoff_usd = estimated_payoff_usd - gas_cost_usd
        
        # Final exploit score
        if effort_base * detection_risk > 0:
            exploit_score = (severity_score * likelihood * (net_payoff_usd / 10000)) / (effort_base * detection_risk)
        else:
            exploit_score = 0
        
        # Risk-adjusted return
        risk_adjusted_return = net_payoff_usd / max(detection_risk * effort_base, 1)
        
        # Priority classification
        if exploit_score > 8:
            priority = "IMMEDIATE_ESCALATION"
            priority_reason = "Critical severity with high likelihood and favorable payoff"
        elif exploit_score > 5:
            priority = "HIGH_PRIORITY"
            priority_reason = "Significant impact with reasonable exploitation effort"
        elif exploit_score > 2:
            priority = "MEDIUM_PRIORITY"
            priority_reason = "Real risk but higher exploitation complexity"
        else:
            priority = "LOW_PRIORITY"
            priority_reason = "Theoretical or very high effort to exploit"
        
        return json.dumps({
            "exploit_score": round(exploit_score, 2),
            "priority": priority,
            "priority_reason": priority_reason,
            "breakdown": {
                "severity_score": severity_score,
                "likelihood": round(likelihood, 3),
                "effort_score": effort_base,
                "detection_risk": detection_risk,
            },
            "economics": {
                "estimated_payoff_usd": round(estimated_payoff_usd, 2),
                "gas_cost_usd": round(gas_cost_usd, 2),
                "net_payoff_usd": round(net_payoff_usd, 2),
                "risk_adjusted_return": round(risk_adjusted_return, 2),
            },
            "recommendations": {
                "should_investigate": exploit_score > 2,
                "needs_poc": exploit_score > 5,
                "immediate_report": exploit_score > 8,
            },
            "path_summary": path.get("path_description", "Unknown path"),
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to score path payoff: {str(e)}",
            "exploit_score": 0,
        })
