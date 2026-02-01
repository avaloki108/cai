"""
Confidence Score Calibration using Platt Scaling

This module provides calibration for confidence scores from security tools
to ensure that predicted probabilities match actual frequencies.

For example, if a tool reports 70% confidence, calibration ensures that
approximately 70% of such findings are actually true positives.
"""

import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json
from pathlib import Path

# Try to import sklearn for Platt scaling
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.calibration import calibration_curve
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class CalibrationMetrics:
    """Metrics for calibration quality."""
    
    tool: str
    vuln_type: str
    n_samples: int
    
    # Before calibration
    uncalibrated_brier: float
    uncalibrated_ece: float  # Expected Calibration Error
    
    # After calibration
    calibrated_brier: float
    calibrated_ece: float
    
    # Platt scaling parameters
    platt_a: float
    platt_b: float
    
    def to_dict(self) -> Dict:
        return {
            "tool": self.tool,
            "vuln_type": self.vuln_type,
            "n_samples": self.n_samples,
            "uncalibrated": {
                "brier_score": self.uncalibrated_brier,
                "ece": self.uncalibrated_ece
            },
            "calibrated": {
                "brier_score": self.calibrated_brier,
                "ece": self.calibrated_ece
            },
            "platt_params": {
                "a": self.platt_a,
                "b": self.platt_b
            },
            "improvement": {
                "brier_reduction": self.uncalibrated_brier - self.calibrated_brier,
                "ece_reduction": self.uncalibrated_ece - self.calibrated_ece
            }
        }


class PlattScaler:
    """
    Platt scaling for probability calibration.
    
    Fits a logistic regression: P(y=1|s) = 1 / (1 + exp(A*s + B))
    where s is the uncalibrated score.
    """
    
    def __init__(self):
        """Initialize the Platt scaler."""
        self.a = 0.0
        self.b = 0.0
        self.fitted = False
        self.model = None
        
        if SKLEARN_AVAILABLE:
            self.model = LogisticRegression()
    
    def fit(
        self,
        scores: np.ndarray,
        labels: np.ndarray
    ) -> 'PlattScaler':
        """
        Fit Platt scaling parameters.
        
        Args:
            scores: Uncalibrated confidence scores (0-1)
            labels: True labels (0 or 1)
            
        Returns:
            Self for chaining
        """
        scores = np.asarray(scores).reshape(-1, 1)
        labels = np.asarray(labels).ravel()
        
        if SKLEARN_AVAILABLE and self.model is not None:
            # Use sklearn's logistic regression
            self.model.fit(scores, labels)
            self.a = float(self.model.coef_[0][0])
            self.b = float(self.model.intercept_[0])
        else:
            # Simple implementation using gradient descent
            self._fit_simple(scores.ravel(), labels)
        
        self.fitted = True
        return self
    
    def _fit_simple(self, scores: np.ndarray, labels: np.ndarray):
        """Simple gradient descent implementation."""
        # Initialize parameters
        a, b = 1.0, 0.0
        lr = 0.01
        n_iterations = 1000
        
        for _ in range(n_iterations):
            # Forward pass
            logits = a * scores + b
            probs = 1 / (1 + np.exp(-logits))
            
            # Compute gradients (negative log-likelihood)
            grad_a = np.mean((probs - labels) * scores)
            grad_b = np.mean(probs - labels)
            
            # Update parameters
            a -= lr * grad_a
            b -= lr * grad_b
        
        self.a = float(a)
        self.b = float(b)
    
    def transform(self, scores: np.ndarray) -> np.ndarray:
        """
        Apply Platt scaling to transform scores.
        
        Args:
            scores: Uncalibrated scores (0-1)
            
        Returns:
            Calibrated probabilities (0-1)
        """
        if not self.fitted:
            raise ValueError("Scaler not fitted. Call fit() first.")
        
        scores = np.asarray(scores).reshape(-1, 1)
        
        if SKLEARN_AVAILABLE and self.model is not None:
            return self.model.predict_proba(scores)[:, 1]
        else:
            logits = self.a * scores.ravel() + self.b
            return 1 / (1 + np.exp(-logits))


class ConfidenceCalibrator:
    """
    Manages calibration for different tools and vulnerability types.
    
    Maintains separate calibration for each (tool, vuln_type) pair
    since different tools and vuln types have different calibration needs.
    """
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize the calibrator.
        
        Args:
            cache_dir: Directory to cache calibration parameters
        """
        self.scalers: Dict[Tuple[str, str], PlattScaler] = {}
        self.metrics: Dict[Tuple[str, str], CalibrationMetrics] = {}
        
        if cache_dir is None:
            cache_dir = str(Path.home() / ".cache" / "cai" / "calibration")
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load cached calibrations
        self._load_cache()
    
    def fit(
        self,
        tool: str,
        vuln_type: str,
        scores: List[float],
        labels: List[int]
    ) -> CalibrationMetrics:
        """
        Fit calibration for a specific (tool, vuln_type) pair.
        
        Args:
            tool: Tool name (e.g., "slither", "mythril")
            vuln_type: Vulnerability type (e.g., "reentrancy")
            scores: Uncalibrated confidence scores
            labels: True labels (1 = true positive, 0 = false positive)
            
        Returns:
            CalibrationMetrics with quality metrics
        """
        scores_arr = np.array(scores)
        labels_arr = np.array(labels)
        
        # Calculate uncalibrated metrics
        uncalib_brier = self._brier_score(scores_arr, labels_arr)
        uncalib_ece = self._expected_calibration_error(scores_arr, labels_arr)
        
        # Fit Platt scaler
        scaler = PlattScaler()
        scaler.fit(scores_arr, labels_arr)
        
        # Calculate calibrated metrics
        calibrated_scores = scaler.transform(scores_arr)
        calib_brier = self._brier_score(calibrated_scores, labels_arr)
        calib_ece = self._expected_calibration_error(calibrated_scores, labels_arr)
        
        # Store scaler
        key = (tool.lower(), vuln_type.lower())
        self.scalers[key] = scaler
        
        # Store metrics
        metrics = CalibrationMetrics(
            tool=tool,
            vuln_type=vuln_type,
            n_samples=len(scores),
            uncalibrated_brier=float(uncalib_brier),
            uncalibrated_ece=float(uncalib_ece),
            calibrated_brier=float(calib_brier),
            calibrated_ece=float(calib_ece),
            platt_a=scaler.a,
            platt_b=scaler.b
        )
        
        self.metrics[key] = metrics
        
        # Save to cache
        self._save_to_cache(tool, vuln_type, scaler, metrics)
        
        return metrics
    
    def calibrate(
        self,
        tool: str,
        vuln_type: str,
        score: float
    ) -> float:
        """
        Calibrate a single confidence score.
        
        Args:
            tool: Tool name
            vuln_type: Vulnerability type
            score: Uncalibrated confidence score
            
        Returns:
            Calibrated probability
        """
        key = (tool.lower(), vuln_type.lower())
        
        if key not in self.scalers:
            # No calibration available, return as-is
            return score
        
        scaler = self.scalers[key]
        return float(scaler.transform(np.array([score]))[0])
    
    def calibrate_batch(
        self,
        findings: List[Dict]
    ) -> List[Dict]:
        """
        Calibrate confidence scores for a batch of findings.
        
        Args:
            findings: List of finding dictionaries with 'tool', 'type', and 'confidence'
            
        Returns:
            Findings with calibrated confidence scores
        """
        calibrated = []
        
        for finding in findings:
            tool = finding.get("tool", "unknown")
            vuln_type = finding.get("type", "unknown")
            confidence = finding.get("confidence", 0.5)
            
            # Convert string confidence to float
            if isinstance(confidence, str):
                conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
                confidence = conf_map.get(confidence.lower(), 0.5)
            
            # Calibrate
            calibrated_conf = self.calibrate(tool, vuln_type, confidence)
            
            # Add calibrated fields
            calibrated_finding = finding.copy()
            calibrated_finding["calibrated_confidence"] = calibrated_conf
            calibrated_finding["original_confidence"] = confidence
            
            calibrated.append(calibrated_finding)
        
        return calibrated
    
    def _brier_score(self, probs: np.ndarray, labels: np.ndarray) -> float:
        """
        Calculate Brier score (mean squared error of probabilities).
        
        Lower is better. Perfect calibration = 0.
        """
        return float(np.mean((probs - labels) ** 2))
    
    def _expected_calibration_error(
        self,
        probs: np.ndarray,
        labels: np.ndarray,
        n_bins: int = 10
    ) -> float:
        """
        Calculate Expected Calibration Error (ECE).
        
        Measures average deviation of predicted probabilities from actual frequencies.
        Lower is better.
        """
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        
        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            # Find samples in this bin
            in_bin = (probs >= bin_lower) & (probs < bin_upper)
            
            if np.sum(in_bin) > 0:
                # Average predicted probability in bin
                avg_pred = np.mean(probs[in_bin])
                
                # Actual frequency of positive class in bin
                avg_true = np.mean(labels[in_bin])
                
                # Weighted contribution to ECE
                bin_weight = np.sum(in_bin) / len(probs)
                ece += bin_weight * abs(avg_pred - avg_true)
        
        return float(ece)
    
    def _save_to_cache(
        self,
        tool: str,
        vuln_type: str,
        scaler: PlattScaler,
        metrics: CalibrationMetrics
    ):
        """Save calibration parameters to cache."""
        key = f"{tool.lower()}_{vuln_type.lower()}"
        cache_file = self.cache_dir / f"{key}.json"
        
        data = {
            "platt_a": scaler.a,
            "platt_b": scaler.b,
            "metrics": metrics.to_dict()
        }
        
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_cache(self):
        """Load cached calibration parameters."""
        if not self.cache_dir.exists():
            return
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Parse tool and vuln_type from filename
                key_str = cache_file.stem
                parts = key_str.split('_', 1)
                if len(parts) == 2:
                    tool, vuln_type = parts
                    key = (tool, vuln_type)
                    
                    # Recreate scaler
                    scaler = PlattScaler()
                    scaler.a = data["platt_a"]
                    scaler.b = data["platt_b"]
                    scaler.fitted = True
                    
                    self.scalers[key] = scaler
                    
            except Exception:
                # Skip invalid cache files
                continue
    
    def get_metrics(self, tool: str, vuln_type: str) -> Optional[CalibrationMetrics]:
        """Get calibration metrics for a (tool, vuln_type) pair."""
        key = (tool.lower(), vuln_type.lower())
        return self.metrics.get(key)
    
    def list_calibrations(self) -> List[Tuple[str, str]]:
        """List all available calibrations."""
        return list(self.scalers.keys())


# Global calibrator instance
_global_calibrator: Optional[ConfidenceCalibrator] = None


def get_calibrator() -> ConfidenceCalibrator:
    """
    Get the global ConfidenceCalibrator instance.
    
    Returns:
        Singleton ConfidenceCalibrator instance
    """
    global _global_calibrator
    
    if _global_calibrator is None:
        _global_calibrator = ConfidenceCalibrator()
    
    return _global_calibrator


__all__ = [
    'PlattScaler',
    'ConfidenceCalibrator',
    'CalibrationMetrics',
    'get_calibrator',
]
