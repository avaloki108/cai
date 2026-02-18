"""
Aegis Agent Evaluation Metrics

Specialized metrics for evaluating the Aegis multi-agent security system:
- Detection accuracy (precision, recall, F1)
- False positive filtering effectiveness
- Economic analysis accuracy
- PoC generation success rate
- Cross-agent coordination efficiency
"""

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    category: str
    severity: str
    description: str
    confidence: float
    validated: bool = False
    poc_generated: bool = False
    poc_successful: bool = False
    
    # Skeptic review scores
    skeptic_alpha_pass: Optional[bool] = None
    skeptic_beta_pass: Optional[bool] = None
    skeptic_gamma_pass: Optional[bool] = None
    
    # Economic analysis
    attack_cost_eth: Optional[float] = None
    attack_profit_eth: Optional[float] = None
    economically_viable: Optional[bool] = None


@dataclass
class AgentMetrics:
    """Metrics for a single agent."""
    agent_name: str
    invocations: int = 0
    total_time_ms: float = 0.0
    findings_processed: int = 0
    errors: int = 0
    
    @property
    def avg_time_ms(self) -> float:
        return self.total_time_ms / self.invocations if self.invocations > 0 else 0.0


@dataclass
class AegisEvaluationResults:
    """Complete Aegis evaluation results."""
    
    # Detection metrics
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Adversarial filtering effectiveness
    findings_before_filter: int = 0
    findings_after_filter: int = 0
    filter_rejection_rate: float = 0.0
    filter_accuracy: float = 0.0  # % of rejections that were correct
    
    # PoC generation metrics
    poc_attempts: int = 0
    poc_generated: int = 0
    poc_compiled: int = 0
    poc_executed: int = 0
    poc_generation_rate: float = 0.0
    poc_success_rate: float = 0.0
    
    # Economic analysis accuracy
    economic_analyses: int = 0
    correct_viability_predictions: int = 0
    economic_accuracy: float = 0.0
    
    # Per-agent metrics
    agent_metrics: Dict[str, AgentMetrics] = field(default_factory=dict)
    
    # Timing
    total_time_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Per-category breakdown
    category_metrics: Dict[str, Dict[str, float]] = field(default_factory=dict)


class AegisEvaluator:
    """Evaluator for Aegis agent ensemble."""
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.ground_truth: Dict[str, bool] = {}  # finding_id -> is_real_vulnerability
        self.agent_metrics: Dict[str, AgentMetrics] = {}
        self.start_time: Optional[float] = None
    
    def start_evaluation(self):
        """Start timing the evaluation."""
        self.start_time = time.time()
        self.findings = []
        self.agent_metrics = {}
    
    def add_finding(self, finding: Finding):
        """Add a finding to track."""
        self.findings.append(finding)
    
    def set_ground_truth(self, finding_id: str, is_real: bool):
        """Set ground truth for a finding."""
        self.ground_truth[finding_id] = is_real
    
    def record_agent_invocation(
        self,
        agent_name: str,
        time_ms: float,
        findings_processed: int = 0,
        error: bool = False
    ):
        """Record metrics for an agent invocation."""
        if agent_name not in self.agent_metrics:
            self.agent_metrics[agent_name] = AgentMetrics(agent_name=agent_name)
        
        metrics = self.agent_metrics[agent_name]
        metrics.invocations += 1
        metrics.total_time_ms += time_ms
        metrics.findings_processed += findings_processed
        if error:
            metrics.errors += 1
    
    def calculate_results(self) -> AegisEvaluationResults:
        """Calculate final evaluation results."""
        results = AegisEvaluationResults()
        
        # Basic counts
        results.total_findings = len(self.findings)
        results.findings_before_filter = len(self.findings)
        
        # Calculate detection metrics against ground truth
        validated_findings = [f for f in self.findings if f.validated]
        results.findings_after_filter = len(validated_findings)
        
        for finding in self.findings:
            is_real = self.ground_truth.get(finding.id, True)  # Assume real if no ground truth
            
            if finding.validated and is_real:
                results.true_positives += 1
            elif finding.validated and not is_real:
                results.false_positives += 1
            elif not finding.validated and is_real:
                results.false_negatives += 1
        
        # Calculate precision, recall, F1
        if results.true_positives + results.false_positives > 0:
            results.precision = results.true_positives / (results.true_positives + results.false_positives)
        
        if results.true_positives + results.false_negatives > 0:
            results.recall = results.true_positives / (results.true_positives + results.false_negatives)
        
        if results.precision + results.recall > 0:
            results.f1_score = 2 * (results.precision * results.recall) / (results.precision + results.recall)
        
        # Filter effectiveness
        if results.findings_before_filter > 0:
            results.filter_rejection_rate = 1 - (results.findings_after_filter / results.findings_before_filter)
        
        rejected = [f for f in self.findings if not f.validated]
        correct_rejections = sum(1 for f in rejected if not self.ground_truth.get(f.id, True))
        if rejected:
            results.filter_accuracy = correct_rejections / len(rejected)
        
        # PoC metrics
        results.poc_attempts = sum(1 for f in validated_findings if f.severity in ["CRITICAL", "HIGH"])
        results.poc_generated = sum(1 for f in self.findings if f.poc_generated)
        results.poc_executed = sum(1 for f in self.findings if f.poc_successful)
        
        if results.poc_attempts > 0:
            results.poc_generation_rate = results.poc_generated / results.poc_attempts
        if results.poc_generated > 0:
            results.poc_success_rate = results.poc_executed / results.poc_generated
        
        # Economic analysis accuracy
        economic_findings = [f for f in self.findings if f.economically_viable is not None]
        results.economic_analyses = len(economic_findings)
        
        for finding in economic_findings:
            is_real = self.ground_truth.get(finding.id, True)
            # Correct if: viable prediction matches reality
            if finding.economically_viable == is_real:
                results.correct_viability_predictions += 1
        
        if results.economic_analyses > 0:
            results.economic_accuracy = results.correct_viability_predictions / results.economic_analyses
        
        # Agent metrics
        results.agent_metrics = {name: metrics for name, metrics in self.agent_metrics.items()}
        
        # Timing
        if self.start_time:
            results.total_time_seconds = time.time() - self.start_time
        
        # Category breakdown
        categories = set(f.category for f in self.findings)
        for category in categories:
            cat_findings = [f for f in self.findings if f.category == category]
            cat_validated = [f for f in cat_findings if f.validated]
            
            cat_tp = sum(1 for f in cat_validated if self.ground_truth.get(f.id, True))
            cat_fp = sum(1 for f in cat_validated if not self.ground_truth.get(f.id, True))
            cat_fn = sum(1 for f in cat_findings if not f.validated and self.ground_truth.get(f.id, True))
            
            cat_precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0
            cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0
            cat_f1 = 2 * (cat_precision * cat_recall) / (cat_precision + cat_recall) if (cat_precision + cat_recall) > 0 else 0.0
            
            results.category_metrics[category] = {
                "precision": cat_precision,
                "recall": cat_recall,
                "f1_score": cat_f1,
                "total": len(cat_findings),
                "validated": len(cat_validated)
            }
        
        return results
    
    def generate_report(self, results: AegisEvaluationResults) -> str:
        """Generate human-readable evaluation report."""
        report = f"""
================================================================================
                    AEGIS EVALUATION REPORT
================================================================================

Generated: {results.timestamp}
Total Evaluation Time: {results.total_time_seconds:.2f}s

================================================================================
                    DETECTION METRICS
================================================================================

Total Findings: {results.total_findings}
True Positives: {results.true_positives}
False Positives: {results.false_positives}
False Negatives: {results.false_negatives}

Precision: {results.precision:.2%}
Recall: {results.recall:.2%}
F1 Score: {results.f1_score:.2%}

================================================================================
                    ADVERSARIAL FILTER EFFECTIVENESS
================================================================================

Findings Before Filter: {results.findings_before_filter}
Findings After Filter: {results.findings_after_filter}
Rejection Rate: {results.filter_rejection_rate:.2%}
Filter Accuracy: {results.filter_accuracy:.2%}

================================================================================
                    POC GENERATION METRICS
================================================================================

PoC Attempts: {results.poc_attempts}
PoC Generated: {results.poc_generated}
PoC Successfully Executed: {results.poc_executed}

Generation Rate: {results.poc_generation_rate:.2%}
Success Rate: {results.poc_success_rate:.2%}

================================================================================
                    ECONOMIC ANALYSIS ACCURACY
================================================================================

Economic Analyses: {results.economic_analyses}
Correct Predictions: {results.correct_viability_predictions}
Accuracy: {results.economic_accuracy:.2%}

================================================================================
                    PER-AGENT METRICS
================================================================================
"""
        
        for name, metrics in results.agent_metrics.items():
            report += f"""
{name}:
  Invocations: {metrics.invocations}
  Avg Time: {metrics.avg_time_ms:.2f}ms
  Findings Processed: {metrics.findings_processed}
  Errors: {metrics.errors}
"""
        
        report += """
================================================================================
                    PER-CATEGORY METRICS
================================================================================
"""
        
        for category, metrics in results.category_metrics.items():
            report += f"""
{category}:
  Total: {metrics['total']}
  Validated: {metrics['validated']}
  Precision: {metrics['precision']:.2%}
  Recall: {metrics['recall']:.2%}
  F1: {metrics['f1_score']:.2%}
"""
        
        report += """
================================================================================
                    TARGET THRESHOLDS
================================================================================

| Metric                | Target  | Actual  | Status |
|-----------------------|---------|---------|--------|
"""
        
        targets = [
            ("Precision", 0.80, results.precision),
            ("Recall", 0.70, results.recall),
            ("F1 Score", 0.75, results.f1_score),
            ("Filter Accuracy", 0.90, results.filter_accuracy),
            ("PoC Success Rate", 0.80, results.poc_success_rate),
            ("Economic Accuracy", 0.85, results.economic_accuracy),
        ]
        
        for name, target, actual in targets:
            status = "✓ PASS" if actual >= target else "✗ FAIL"
            report += f"| {name:21} | {target:6.0%} | {actual:6.0%} | {status} |\n"
        
        report += "\n================================================================================\n"
        
        return report
    
    def save_results(self, results: AegisEvaluationResults, output_path: str):
        """Save results to JSON file."""
        output = {
            "evaluation": "Aegis",
            "timestamp": results.timestamp,
            "detection_metrics": {
                "precision": results.precision,
                "recall": results.recall,
                "f1_score": results.f1_score,
                "true_positives": results.true_positives,
                "false_positives": results.false_positives,
                "false_negatives": results.false_negatives,
            },
            "filter_metrics": {
                "before": results.findings_before_filter,
                "after": results.findings_after_filter,
                "rejection_rate": results.filter_rejection_rate,
                "accuracy": results.filter_accuracy,
            },
            "poc_metrics": {
                "attempts": results.poc_attempts,
                "generated": results.poc_generated,
                "executed": results.poc_executed,
                "generation_rate": results.poc_generation_rate,
                "success_rate": results.poc_success_rate,
            },
            "economic_metrics": {
                "analyses": results.economic_analyses,
                "correct_predictions": results.correct_viability_predictions,
                "accuracy": results.economic_accuracy,
            },
            "agent_metrics": {
                name: {
                    "invocations": m.invocations,
                    "avg_time_ms": m.avg_time_ms,
                    "findings_processed": m.findings_processed,
                    "errors": m.errors,
                }
                for name, m in results.agent_metrics.items()
            },
            "category_metrics": results.category_metrics,
            "total_time_seconds": results.total_time_seconds,
        }
        
        Path(output_path).write_text(json.dumps(output, indent=2))


def run_aegis_evaluation(
    findings: List[Dict[str, Any]],
    ground_truth: Dict[str, bool],
    output_path: Optional[str] = None,
    verbose: bool = True
) -> AegisEvaluationResults:
    """
    Run Aegis evaluation on a set of findings.
    
    Args:
        findings: List of finding dictionaries
        ground_truth: Map of finding_id -> is_real_vulnerability
        output_path: Optional path to save results
        verbose: Print progress
        
    Returns:
        AegisEvaluationResults
    """
    evaluator = AegisEvaluator()
    evaluator.start_evaluation()
    
    # Set ground truth
    for finding_id, is_real in ground_truth.items():
        evaluator.set_ground_truth(finding_id, is_real)
    
    # Process findings
    for f in findings:
        finding = Finding(
            id=f.get("id", "unknown"),
            category=f.get("category", "unknown"),
            severity=f.get("severity", "MEDIUM"),
            description=f.get("description", ""),
            confidence=f.get("confidence", 0.5),
            validated=f.get("validated", False),
            poc_generated=f.get("poc_generated", False),
            poc_successful=f.get("poc_successful", False),
            skeptic_alpha_pass=f.get("skeptic_alpha_pass"),
            skeptic_beta_pass=f.get("skeptic_beta_pass"),
            skeptic_gamma_pass=f.get("skeptic_gamma_pass"),
            economically_viable=f.get("economically_viable"),
        )
        evaluator.add_finding(finding)
    
    # Calculate results
    results = evaluator.calculate_results()
    
    if verbose:
        print(evaluator.generate_report(results))
    
    if output_path:
        evaluator.save_results(results, output_path)
        if verbose:
            print(f"Results saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    # Demo with synthetic data
    demo_findings = [
        {"id": "VUL-001", "category": "reentrancy", "severity": "CRITICAL", "validated": True, "poc_generated": True, "poc_successful": True, "economically_viable": True},
        {"id": "VUL-002", "category": "access_control", "severity": "HIGH", "validated": True, "poc_generated": True, "poc_successful": False, "economically_viable": True},
        {"id": "VUL-003", "category": "front_running", "severity": "MEDIUM", "validated": False, "economically_viable": False},
        {"id": "VUL-004", "category": "arithmetic", "severity": "LOW", "validated": True, "poc_generated": False, "economically_viable": True},
    ]
    
    demo_ground_truth = {
        "VUL-001": True,
        "VUL-002": True,
        "VUL-003": False,  # False positive correctly rejected
        "VUL-004": True,
    }
    
    results = run_aegis_evaluation(
        demo_findings,
        demo_ground_truth,
        output_path="benchmarks/metrics/aegis_demo_results.json"
    )
