"""
Multi-Tool Orchestrator

This module aggregates and correlates findings from multiple security tools,
generating a unified strategic digest for the agent.

The orchestrator acts as the "reasoning layer" on top of tool "sensors".

Enhanced with:
- Real similarity scoring for correlation (not just location matching)
- Proper use of correlation_threshold parameter
- Improved confidence calculation
"""

import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Union
from collections import defaultdict
from cai.sdk.agents import function_tool
from ..finding_schema import ensure_finding_dict
from ..symbolic.constraint_analyzer import extract_constraints_from_mythril, extract_constraints_from_oyente, PathConstraint
from ..symbolic.correlator import SymbolicStaticCorrelator
from ..taxonomy import map_to_dasp





# =============================================================================
# Similarity Helpers for Real Correlation
# =============================================================================

try:
    from cai.ml.embeddings import get_embedder
    _embedder = get_embedder()
except Exception:  # pragma: no cover - optional dependency
    _embedder = None

_EMBED_CACHE_MAX = int(os.getenv("CAI_EMBED_CACHE_MAX", "1024"))
_embed_cache: Dict[str, List[float]] = {}


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    denom = (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(x * x for x in b))) or 1.0
    return sum(x * y for x, y in zip(a, b)) / denom


def _embed_text(text: str) -> Optional[List[float]]:
    if not _embedder:
        return None
    cached = _embed_cache.get(text)
    if cached is not None:
        return cached
    try:
        emb = _embedder.embed_code(text, normalize=True)
        vec = emb.tolist() if hasattr(emb, "tolist") else list(emb)
        if len(_embed_cache) >= _EMBED_CACHE_MAX:
            _embed_cache.clear()
        _embed_cache[text] = vec
        return vec
    except Exception:
        return None


def _embedding_similarity(f1: Dict, f2: Dict) -> Optional[float]:
    text1 = f"{f1.get('type', '')} {f1.get('description', '')} {f1.get('location', '')}"
    text2 = f"{f2.get('type', '')} {f2.get('description', '')} {f2.get('location', '')}"
    v1 = _embed_text(text1)
    v2 = _embed_text(text2)
    if v1 is None or v2 is None:
        return None
    return _cosine(v1, v2)



def _tok(s: str) -> set:
    """Tokenize a string into lowercase alphanumeric tokens."""
    return set(re.findall(r"[a-z0-9_]+", (s or "").lower()))


def _jaccard(a: str, b: str) -> float:
    """Calculate Jaccard similarity between two strings."""
    A, B = _tok(a), _tok(b)
    if not A and not B:
        return 1.0
    if not A or not B:
        return 0.0
    return len(A & B) / max(1, len(A | B))


def _finding_similarity(f1: Dict, f2: Dict) -> float:
    """
    Calculate weighted similarity between two findings.
    
    Weights:
    - Category match: 30%
    - Type similarity: 15%
    - Description similarity: 20%
    - Embedding similarity: 20% (if available)
    - Location similarity: 10%
    - File match: 5%
    """
    # Category match (exact)
    cat = 1.0 if f1.get("category") == f2.get("category") else 0.0

    # Type similarity (Jaccard)
    t = _jaccard(f1.get("type", ""), f2.get("type", ""))

    # Description similarity (Jaccard)
    d = _jaccard(f1.get("description", ""), f2.get("description", ""))

    # Embedding similarity (if available)
    sem = _embedding_similarity(f1, f2)
    if sem is None:
        sem = 0.0

    # Location similarity (Jaccard on stringified location)
    loc_sim = _jaccard(str(f1.get("location", "")), str(f2.get("location", "")))

    # File match (exact, if both have one)
    file1 = f1.get("file")
    file2 = f2.get("file")
    file_match = 1.0 if (file1 and file1 == file2) else 0.0

    return 0.30 * cat + 0.15 * t + 0.20 * d + 0.20 * sem + 0.10 * loc_sim + 0.05 * file_match


def _base_confidence(c: Any) -> float:
    """
    Parse confidence value to float (0-1).
    
    Handles numeric values and string mappings.
    """
    if isinstance(c, (int, float)):
        return max(0.0, min(1.0, float(c)))
    if isinstance(c, str):
        m = {"high": 0.85, "medium": 0.55, "low": 0.30, "info": 0.20, "informational": 0.20}
        return m.get(c.lower(), 0.50)
    return 0.50


# =============================================================================
# Tool output normalization mappings
# =============================================================================
SEVERITY_NORMALIZATION = {
    # Slither
    "high": "HIGH",
    "medium": "MEDIUM", 
    "low": "LOW",
    "informational": "INFO",
    "optimization": "INFO",
    
    # Mythril
    "Warning": "MEDIUM",
    "Error": "HIGH",
    
    # General
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

# Finding type normalization
TYPE_NORMALIZATION = {
    # Slither detector names to categories
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "arbitrary-send-erc20": "access_control",
    "arbitrary-send-eth": "access_control",
    "unprotected-upgrade": "upgradeability",
    "suicidal": "access_control",
    "controlled-delegatecall": "external_call",
    "delegatecall-loop": "external_call",
    "unchecked-lowlevel": "external_call",
    "unchecked-transfer": "token_handling",
    "uninitialized-state": "initialization",
    "uninitialized-local": "initialization",
    "unused-state": "code_quality",
    "unused-return": "unchecked_return",
    "shadowing-state": "shadowing",
    "shadowing-local": "shadowing",
    "timestamp": "timestamp",
    "assembly": "assembly",
    "locked-ether": "locked_funds",
    "naming-convention": "style",
    "pragma": "pragma",
    "solc-version": "compiler",
    
    # Mythril
    "integer_overflow": "arithmetic",
    "integer_underflow": "arithmetic",
    "ether_thief": "access_control",
    "state_change_external_calls": "reentrancy",
    "multiple_sends": "reentrancy",
    
    # Generic categories
    "oracle": "oracle",
    "price": "oracle",
    "flash": "flash_loan",
    "flash-loan": "flash_loan",
    "flashloan": "flash_loan",
    "mev": "mev",
    "sandwich": "mev",
    "governance": "governance",
    "timelock": "governance",
    "bridge": "bridge",
    "cross-chain": "bridge",
    "erc4626": "accounting",
    "share": "accounting",
    "fee-on-transfer": "token_handling",
    "permit": "signature",
    "signature": "signature",
}


def _normalize_severity(severity: str) -> str:
    """Normalize severity to standard format."""
    if isinstance(severity, str):
        return SEVERITY_NORMALIZATION.get(severity.lower(), severity.upper())
    return "MEDIUM"


def _normalize_type(finding_type: str) -> str:
    """Normalize finding type to category."""
    if not finding_type:
        return "unknown"
    
    normalized = finding_type.lower().replace("_", "-").replace(" ", "-")
    
    # Check for exact match
    if normalized in TYPE_NORMALIZATION:
        return TYPE_NORMALIZATION[normalized]
    
    # Check for partial match
    for key, value in TYPE_NORMALIZATION.items():
        if key in normalized:
            return value
    
    return normalized


def _extract_location_key(finding: Dict) -> str:
    """Extract a unique location key for deduplication."""
    location = finding.get("location", "")

    if isinstance(location, dict):
        filename = location.get("filename") or location.get("file") or ""
        line = location.get("line") or location.get("lines")
        if filename and line:
            return f"{filename}:{line}"
        if filename:
            return filename
        return json.dumps(location, sort_keys=True)

    if isinstance(location, str) and location:
        return location

    file_path = finding.get("file")
    if file_path:
        start = finding.get("line_start")
        end = finding.get("line_end")
        if start and end:
            return f"{file_path}:{start}-{end}"
        if start:
            return f"{file_path}:{start}"
        return file_path

    return ""


def _constraint_from_dict(c_dict: Dict[str, Any]) -> PathConstraint:
    loc = c_dict.get("location", {}) or {}
    return PathConstraint(
        source_tool=c_dict.get("source_tool", "unknown"),
        constraint_smt=c_dict.get("constraint_smt", ""),
        constraint_type=c_dict.get("constraint_type", "unknown"),
        contract=loc.get("contract", "unknown"),
        function=loc.get("function", "unknown"),
        pc=loc.get("pc"),
        line=loc.get("line"),
        affected_state_vars=c_dict.get("state_vars", []),
        involved_variables=set(c_dict.get("variables", [])),
        feasibility_score=c_dict.get("feasibility", 1.0),
        complexity=c_dict.get("complexity", 0),
    )


@function_tool
def aggregate_tool_results(results: str, ctf=None) -> str:
    """
    Aggregate and normalize results from multiple security tools.
    
    Takes outputs from different tools (Slither, Mythril, etc.) and
    combines them into a unified format for analysis.
    
    Args:
        results: JSON string with tool results. Format:
                 {"tool_name": [findings], ...} or
                 [{"tool": "...", "findings": [...]}]
    
    Returns:
        JSON string with aggregated, normalized findings.
    
    Example:
        aggregate_tool_results('{"slither": [...], "mythril": [...]}')
    """
    try:
        if isinstance(results, str):
            results_data = json.loads(results)
        else:
            results_data = results
        

        # Normalize input format
        if isinstance(results_data, list):
            tool_results = {}
            for item in results_data:
                tool_name = item.get("tool", "unknown")
                tool_results[tool_name] = item.get("findings", item.get("results", []))
        else:
            tool_results = results_data

        # Collect symbolic constraints if raw tool output is available
        symbolic_constraints = []

        # Aggregate and normalize findings
        all_findings = []
        tool_stats = defaultdict(lambda: {
            "count": 0,
            "by_severity": defaultdict(int)
        })

        for tool_name, tool_findings in tool_results.items():
            if not tool_findings:
                continue

            # If we have raw mythril/oyente output, extract constraints
            if isinstance(tool_findings, dict):
                if tool_name.lower() == "mythril":
                    symbolic_constraints.extend(
                        [c.to_dict() for c in extract_constraints_from_mythril(tool_findings)]
                    )
                if tool_name.lower() == "oyente":
                    symbolic_constraints.extend(
                        [c.to_dict() for c in extract_constraints_from_oyente(tool_findings)]
                    )
                tool_findings = (
                    tool_findings.get("findings")
                    or tool_findings.get("issues")
                    or tool_findings.get("results")
                    or []
                )

            for finding in tool_findings:
                normalized_input = ensure_finding_dict(finding, tool_name).to_dict()
                finding_type = normalized_input.get("type", "unknown")
                severity = normalized_input.get("severity", finding.get("impact", "medium"))

                normalized_finding = {
                    **normalized_input,
                    "id": normalized_input.get("id") or f"{tool_name}_{len(all_findings)}",
                    "tool": tool_name,
                    "type": finding_type,
                    "category": _normalize_type(finding_type),
                    "taxonomy": {
                        "dasp": map_to_dasp(_normalize_type(finding_type)),
                    },
                    "severity": _normalize_severity(severity),
                    "severity_original": severity,
                    "confidence": normalized_input.get("confidence", finding.get("confidence", "medium")),
                    "location_key": _extract_location_key(normalized_input),
                }

                all_findings.append(normalized_finding)
                tool_stats[tool_name]["by_severity"][normalized_finding["severity"]] += 1
        
        # Calculate aggregated statistics
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for finding in all_findings:
            severity_counts[finding["severity"]] += 1
            category_counts[finding["category"]] += 1
        
        return json.dumps({
            "findings": all_findings,
            "tool_stats": tool_stats,
            "summary": {
                "total_findings": len(all_findings),
                "unique_categories": len(category_counts),
                "severity_breakdown": dict(severity_counts),
                "category_breakdown": dict(category_counts)
            },
            "symbolic_constraints": symbolic_constraints,
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to aggregate results: {str(e)}",
            "findings": [],
        })


@function_tool
def correlate_findings(findings: str, correlation_threshold: float = 0.7, ctf=None) -> str:
    """
    Find related findings across different tools using real similarity scoring.
    
    Identifies when multiple tools flag the same issue, which
    increases confidence in the finding's validity.
    
    Uses weighted similarity (category, type, description, location) to ensure
    correlation_threshold is meaningful - not just location matching.
    
    Args:
        findings: JSON string of aggregated findings from aggregate_tool_results().
        correlation_threshold: Minimum similarity for correlation (0-1).
                              Default 0.7 means findings must be 70% similar.
    
    Returns:
        JSON string with correlated finding groups and confidence boost.
    
    Example:
        correlate_findings(aggregated_findings_json, correlation_threshold=0.6)
    """
    try:
        if isinstance(findings, str):
            findings_data = json.loads(findings)
        else:
            findings_data = findings
        
        all_findings = findings_data.get("findings", findings_data)
        if not isinstance(all_findings, list):
            all_findings = [all_findings]
        
        # Group findings by location
        location_groups = defaultdict(list)
        for finding in all_findings:
            location_key = finding.get("location_key", _extract_location_key(finding))
            location_groups[location_key].append(finding)
        
        # Group findings by category
        category_groups = defaultdict(list)
        for finding in all_findings:
            category = finding.get("category", "unknown")
            category_groups[category].append(finding)
        
        # Find correlations
        correlations = []
        
        # Location-based correlations (same location, different tools)
        # NOW WITH REAL SIMILARITY CHECK
        for location, group in location_groups.items():
            if len(group) > 1:
                tools = list(set(f.get("tool", "unknown") for f in group))
                if len(tools) > 1:  # Multiple tools found same location
                    # =========================================================
                    # NEW: Ensure findings are truly the "same" issue using
                    # similarity scoring, not just same line/function
                    # =========================================================
                    sim_ok = False
                    max_similarity = 0.0
                    
                    for i in range(len(group)):
                        for j in range(i + 1, len(group)):
                            similarity = _finding_similarity(group[i], group[j])
                            max_similarity = max(max_similarity, similarity)
                            if similarity >= correlation_threshold:
                                sim_ok = True
                                break
                        if sim_ok:
                            break
                    
                    # Skip if findings don't meet similarity threshold
                    if not sim_ok:
                        continue
                    
                    # Calculate confidence boost (scaled by similarity)
                    base_boost = min(0.3 * (len(tools) - 1), 0.9)
                    confidence_boost = base_boost * max_similarity
                    
                    correlations.append({
                        "type": "location_correlation",
                        "location": location,
                        "finding_count": len(group),
                        "tools": tools,
                        "similarity_score": round(max_similarity, 3),
                        "correlation_threshold_used": correlation_threshold,
                        "confidence_boost": round(confidence_boost, 3),
                        "findings": [f["id"] for f in group],
                        "max_severity": max(
                            (f.get("severity", "LOW") for f in group),
                            key=lambda s: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(s, 0)
                        ),
                        "categories": list(set(f.get("category", "unknown") for f in group)),
                    })
        
        # Category-based correlations (same category across contracts)
        for category, group in category_groups.items():
            if len(group) >= 3:  # Pattern of similar issues
                contracts = list(
                    set(
                        (f.get("file") or str(f.get("location", "")).split(":")[0])
                        for f in group
                        if (f.get("file") or f.get("location"))
                    )
                )
                if len(contracts) >= 2:
                    correlations.append({
                        "type": "category_pattern",
                        "category": category,
                        "finding_count": len(group),
                        "contracts_affected": contracts[:5],
                        "pattern_description": f"Multiple {category} issues across {len(contracts)} contracts",
                        "findings": [f["id"] for f in group][:10],
                    })
        
        # Calculate enhanced findings with improved confidence
        enhanced_findings = []
        correlation_map = {}
        symbolic_boost_map = {}

        # Add symbolic correlation boosts if symbolic constraints are available
        symbolic_constraints = findings_data.get("symbolic_constraints", [])
        if symbolic_constraints:
            correlator = SymbolicStaticCorrelator()
            constraints = [
                _constraint_from_dict(c) for c in symbolic_constraints if isinstance(c, dict)
            ]
            correlated = correlator.correlate_findings(
                all_findings,
                constraints,
                correlation_threshold=correlation_threshold,
            )
            for corr in correlated:
                corr_dict = corr.to_dict()
                corr_dict["type"] = "symbolic_correlation"
                correlations.append(corr_dict)
                fid = corr.static_finding.get("id")
                if fid:
                    symbolic_boost_map[fid] = max(
                        symbolic_boost_map.get(fid, 0),
                        corr.confidence_boost,
                    )

        for corr in correlations:
            if corr["type"] == "location_correlation":
                for fid in corr["findings"]:
                    # Store the higher boost if multiple correlations
                    existing = correlation_map.get(fid, 0)
                    correlation_map[fid] = max(existing, corr["confidence_boost"])

        # Merge symbolic boosts into correlation map
        for fid, boost in symbolic_boost_map.items():
            correlation_map[fid] = max(correlation_map.get(fid, 0), boost)

        for finding in all_findings:
            enhanced = finding.copy()
            fid = finding.get("id", "")

            if fid in correlation_map:
                enhanced["correlated"] = True
                enhanced["confidence_boost"] = correlation_map[fid]
                enhanced["symbolic_boost"] = symbolic_boost_map.get(fid, 0)
                # Use improved confidence calculation
                base = _base_confidence(finding.get("confidence", "medium"))
                enhanced["effective_confidence"] = min(1.0, base + correlation_map[fid])
                enhanced["base_confidence"] = round(base, 3)
            else:
                enhanced["correlated"] = False
                enhanced["confidence_boost"] = 0
                enhanced["symbolic_boost"] = 0
                enhanced["effective_confidence"] = _base_confidence(finding.get("confidence", "medium"))

            enhanced_findings.append(enhanced)
        
        return json.dumps({
            "correlations": correlations,
            "enhanced_findings": enhanced_findings,
            "summary": {
                "total_correlations": len(correlations),
                "location_correlations": len([c for c in correlations if c["type"] == "location_correlation"]),
                "category_patterns": len([c for c in correlations if c["type"] == "category_pattern"]),
                "symbolic_correlations": len([c for c in correlations if c["type"] == "symbolic_correlation"]),
                "findings_with_correlation": len([f for f in enhanced_findings if f.get("correlated")]),
                "correlation_threshold": correlation_threshold,
            },
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to correlate findings: {str(e)}",
            "correlations": [],
        })


@function_tool
def generate_strategic_digest(aggregated_results: str, ctf=None) -> str:
    """
    Generate a strategic digest for agent decision-making.
    
    Creates a prioritized action plan based on aggregated and correlated
    findings, following game-theoretic prioritization principles.
    
    Args:
        aggregated_results: JSON string from aggregate_tool_results() or correlate_findings().
    
    Returns:
        JSON string with strategic digest including:
        - Priority actions
        - Attack surface summary
        - Recommended next steps
        - Effort allocation guidance
    
    Example:
        generate_strategic_digest(correlated_findings_json)
    """
    try:
        if isinstance(aggregated_results, str):
            data = json.loads(aggregated_results)
        else:
            data = aggregated_results
        
        # Extract findings
        findings = data.get("enhanced_findings", data.get("findings", []))
        if not isinstance(findings, list):
            findings = [findings]
        
        # Categorize by severity
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high = [f for f in findings if f.get("severity") == "HIGH"]
        medium = [f for f in findings if f.get("severity") == "MEDIUM"]
        low = [f for f in findings if f.get("severity") in ["LOW", "INFO"]]
        
        # Identify correlated (high confidence) findings
        correlated = [f for f in findings if f.get("correlated")]
        
        # Build priority actions
        priority_actions = []
        
        # Critical findings are immediate priority
        for f in critical[:5]:
            priority_actions.append({
                "priority": 1,
                "action": "IMMEDIATE_INVESTIGATION",
                "finding_type": f.get("type"),
                "category": f.get("category"),
                "location": f.get("location"),
                "reason": "Critical severity requires immediate attention",
            })
        
        # Correlated high findings are next
        correlated_high = [f for f in high if f.get("correlated")]
        for f in correlated_high[:3]:
            priority_actions.append({
                "priority": 2,
                "action": "HIGH_CONFIDENCE_INVESTIGATION",
                "finding_type": f.get("type"),
                "category": f.get("category"),
                "reason": f"High severity with multi-tool correlation (confidence boost: {f.get('confidence_boost', 0)})",
            })
        
        # Non-correlated high findings
        non_correlated_high = [f for f in high if not f.get("correlated")]
        for f in non_correlated_high[:3]:
            priority_actions.append({
                "priority": 3,
                "action": "VALIDATE_FINDING",
                "finding_type": f.get("type"),
                "category": f.get("category"),
                "reason": "High severity but single tool - needs validation",
            })
        
        # Attack surface summary
        categories = defaultdict(int)
        for f in findings:
            categories[f.get("category", "unknown")] += 1
        
        attack_surface = []
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
            high_risk = {
                "reentrancy",
                "access_control",
                "oracle",
                "flash_loan",
                "bridge",
                "governance",
                "liquidation",
                "upgradeability",
                "mev",
            }
            attack_surface.append({
                "category": category,
                "finding_count": count,
                "risk_level": "HIGH" if category in high_risk else "MEDIUM",
            })
        
        # Recommended workflow
        workflow = []
        
        if critical:
            workflow.append({
                "step": 1,
                "action": "Address critical findings",
                "focus": [f.get("category") for f in critical[:3]],
                "effort_allocation": "40%",
            })
        
        if correlated_high:
            workflow.append({
                "step": 2 if critical else 1,
                "action": "Validate correlated high-severity findings",
                "focus": list(set(f.get("category") for f in correlated_high[:5])),
                "effort_allocation": "30%",
            })
        
        # =================================================================
        # NEW: If no correlated findings, recommend cross-validation
        # This keeps the agent tight in repo mode instead of expanding scope
        # =================================================================
        if not correlated and high:
            workflow.append({
                "step": len(workflow) + 1,
                "action": "VALIDATE: Run alternative tool on top 3 high-severity findings",
                "focus": list(set(f.get("category") for f in high[:3])),
                "effort_allocation": "25%",
                "reason": "No multi-tool correlation - need validation before trusting",
            })
        
        if attack_surface and correlated:
            # Only explore attack surfaces if we have correlated findings
            workflow.append({
                "step": len(workflow) + 1,
                "action": "Explore top attack surfaces",
                "focus": [a["category"] for a in attack_surface[:3]],
                "effort_allocation": "20%",
            })
        elif attack_surface and not correlated:
            # More conservative if no correlation
            workflow.append({
                "step": len(workflow) + 1,
                "action": "Selective exploration of highest-risk attack surfaces only",
                "focus": [a["category"] for a in attack_surface[:2] if a.get("risk_level") == "HIGH"],
                "effort_allocation": "15%",
                "reason": "Limited exploration due to lack of correlation",
            })
        
        workflow.append({
            "step": len(workflow) + 1,
            "action": "COUNCIL_FALSE_POSITIVE_GATE",
            "effort_allocation": "10%",
            "notes": "Run council_filter_findings() to enforce permissionless-only findings and evidence requirements.",
        })
        workflow.append({
            "step": len(workflow) + 1,
            "action": "Document and report validated findings",
            "effort_allocation": "10%",
        })
        
        # Overall assessment
        if critical:
            overall_risk = "CRITICAL"
            assessment = "Critical vulnerabilities detected - immediate action required"
        elif high:
            overall_risk = "HIGH"
            assessment = f"{len(high)} high-severity findings require investigation"
        elif medium:
            overall_risk = "MEDIUM"
            assessment = f"{len(medium)} medium-severity findings warrant review"
        else:
            overall_risk = "LOW"
            assessment = "No high-impact findings detected, consider deeper analysis"
        
        return json.dumps({
            "strategic_digest": {
                "overall_risk": overall_risk,
                "assessment": assessment,
                "findings_summary": {
                    "critical": len(critical),
                    "high": len(high),
                    "medium": len(medium),
                    "low": len(low),
                    "total": len(findings),
                    "correlated": len(correlated),
                },
            },
            "priority_actions": priority_actions,
            "attack_surface": attack_surface,
            "recommended_workflow": workflow,
            "agent_guidance": {
                "next_step": priority_actions[0]["action"] if priority_actions else "COMPREHENSIVE_REVIEW",
                "focus_category": priority_actions[0]["category"] if priority_actions else attack_surface[0]["category"] if attack_surface else "general",
                "time_box_suggestion": "Focus 40% of effort on top 3 priority actions",
                # New: correlation-aware guidance
                "correlation_status": "VALIDATED" if correlated else "NEEDS_VALIDATION",
                "validation_guidance": (
                    "Findings have multi-tool correlation - proceed with confidence"
                    if correlated else
                    "NO CORRELATION: Validate top 3 high-severity findings with different tool before expanding scope"
                ),
            },
        }, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to generate strategic digest: {str(e)}",
            "strategic_digest": {},
        })
