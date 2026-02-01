"""
Vulnerability Classifier using XGBoost

This module provides a trained classifier to predict whether a security
finding is a true positive or false positive based on features extracted
from the code and tool outputs.

Features used:
- Code embeddings (from SmartBERT)
- Tool confidence scores
- Finding type (one-hot encoded)
- Context features (has modifiers, requires, etc.)
"""

import os
import json
import pickle
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

# Try to import ML libraries
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Import embedder
try:
    from cai.ml.embeddings import get_embedder
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False


@dataclass
class ClassificationResult:
    """Result of vulnerability classification."""
    
    is_true_positive: bool
    probability: float
    confidence: float
    reasoning: str
    feature_importance: Dict[str, float]


class VulnerabilityClassifier:
    """
    XGBoost classifier for vulnerability true positive prediction.
    
    Trained on historical audit data to distinguish between real
    vulnerabilities and false positives.
    """
    
    # Common vulnerability types for one-hot encoding
    VULN_TYPES = [
        "reentrancy",
        "access_control",
        "oracle",
        "flash_loan",
        "integer_overflow",
        "unchecked_call",
        "delegatecall",
        "timestamp",
        "front_running",
        "dos",
        "signature",
        "proxy",
        "other"
    ]
    
    # Context features to extract from code
    CONTEXT_FEATURES = [
        "has_nonreentrant",
        "has_onlyowner",
        "has_require",
        "has_modifier",
        "has_timelock",
        "has_pausable",
        "is_view_function",
        "is_pure_function",
        "has_external_call",
        "has_state_update"
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the classifier.
        
        Args:
            model_path: Path to pre-trained model file (.pkl or .json)
        """
        self.model = None
        self.embedder = None
        self.feature_names = []
        
        if XGBOOST_AVAILABLE:
            if model_path and Path(model_path).exists():
                self.load_model(model_path)
            else:
                # Initialize with default parameters
                self.model = xgb.XGBClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    objective='binary:logistic',
                    eval_metric='auc'
                )
        
        if EMBEDDINGS_AVAILABLE:
            self.embedder = get_embedder()
    
    def extract_features(
        self,
        finding: Dict[str, Any],
        code_context: str = ""
    ) -> np.ndarray:
        """
        Extract features from a finding for classification.
        
        Args:
            finding: Dictionary containing finding information
            code_context: Source code context
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # 1. Code embeddings (768 dimensions from SmartBERT)
        if self.embedder is not None and code_context:
            emb = self.embedder.embed_code(code_context, normalize=True)
            features.extend(emb.tolist())
        else:
            # Placeholder if no embeddings
            features.extend([0.0] * 768)
        
        # 2. Tool confidence score
        confidence = finding.get("confidence", 0.5)
        if isinstance(confidence, str):
            conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
            confidence = conf_map.get(confidence.lower(), 0.5)
        features.append(float(confidence))
        
        # 3. Severity score
        severity = finding.get("severity", "medium")
        sev_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        features.append(sev_map.get(severity.lower(), 0.5))
        
        # 4. Vulnerability type (one-hot encoded)
        finding_type = finding.get("type", "other").lower()
        type_vector = [0.0] * len(self.VULN_TYPES)
        for i, vtype in enumerate(self.VULN_TYPES):
            if vtype in finding_type or finding_type in vtype:
                type_vector[i] = 1.0
                break
        else:
            type_vector[-1] = 1.0  # "other"
        features.extend(type_vector)
        
        # 5. Context features (extracted from code)
        if code_context:
            code_lower = code_context.lower()
            context_vec = [
                float("nonreentrant" in code_lower),
                float("onlyowner" in code_lower or "onlyadmin" in code_lower),
                float("require(" in code_lower),
                float("modifier" in code_lower),
                float("timelock" in code_lower),
                float("pausable" in code_lower or "paused" in code_lower),
                float("view" in code_lower),
                float("pure" in code_lower),
                float("call(" in code_lower or "delegatecall(" in code_lower),
                float("=" in code_lower and "state" in code_lower)
            ]
            features.extend(context_vec)
        else:
            features.extend([0.0] * len(self.CONTEXT_FEATURES))
        
        # 6. Tool-specific features
        tool = finding.get("tool", "unknown").lower()
        tool_vector = [
            float(tool == "slither"),
            float(tool == "mythril"),
            float(tool == "echidna"),
            float(tool == "medusa"),
            float(tool == "manticore")
        ]
        features.extend(tool_vector)
        
        return np.array(features)
    
    def predict(
        self,
        finding: Dict[str, Any],
        code_context: str = ""
    ) -> ClassificationResult:
        """
        Predict whether a finding is a true positive.
        
        Args:
            finding: Finding dictionary
            code_context: Source code context
            
        Returns:
            ClassificationResult with prediction and probability
        """
        # Extract features
        features = self.extract_features(finding, code_context)
        
        # If no model available, use heuristic
        if self.model is None or not XGBOOST_AVAILABLE:
            return self._heuristic_classify(finding, code_context)
        
        # Predict
        features_reshaped = features.reshape(1, -1)
        probability = float(self.model.predict_proba(features_reshaped)[0][1])
        is_true_positive = probability >= 0.5
        
        # Calculate confidence (distance from decision boundary)
        confidence = abs(probability - 0.5) * 2
        
        # Generate reasoning
        if is_true_positive:
            reasoning = f"Classified as TRUE POSITIVE with {probability:.1%} probability. "
            reasoning += "Model detects strong vulnerability indicators in code patterns."
        else:
            reasoning = f"Classified as FALSE POSITIVE with {(1-probability):.1%} probability. "
            reasoning += "Model detects protective mechanisms or benign patterns."
        
        # Get feature importance
        feature_importance = {}
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            # Get top 5 features
            top_indices = np.argsort(importances)[::-1][:5]
            for idx in top_indices:
                if idx < len(self.feature_names):
                    feature_importance[self.feature_names[idx]] = float(importances[idx])
        
        return ClassificationResult(
            is_true_positive=is_true_positive,
            probability=probability,
            confidence=confidence,
            reasoning=reasoning,
            feature_importance=feature_importance
        )
    
    def _heuristic_classify(
        self,
        finding: Dict[str, Any],
        code_context: str
    ) -> ClassificationResult:
        """
        Fallback heuristic classification when XGBoost is not available.
        
        Uses simple rules based on severity, confidence, and code patterns.
        """
        # Start with base probability from confidence
        confidence = finding.get("confidence", 0.5)
        if isinstance(confidence, str):
            conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
            probability = conf_map.get(confidence.lower(), 0.5)
        else:
            probability = float(confidence)
        
        # Adjust based on severity
        severity = finding.get("severity", "medium").lower()
        if severity == "critical":
            probability *= 1.2
        elif severity == "low":
            probability *= 0.8
        
        # Reduce probability if protective patterns found
        if code_context:
            code_lower = code_context.lower()
            reductions = 0
            
            if "nonreentrant" in code_lower:
                reductions += 1
            if "onlyowner" in code_lower or "onlyadmin" in code_lower:
                reductions += 1
            if "require(" in code_lower:
                reductions += 0.5
            if "view" in code_lower or "pure" in code_lower:
                reductions += 1
            
            probability *= (0.8 ** reductions)
        
        # Cap probability
        probability = min(max(probability, 0.0), 1.0)
        
        is_true_positive = probability >= 0.5
        confidence_score = abs(probability - 0.5) * 2
        
        reasoning = f"Heuristic classification: {probability:.1%} probability of true positive. "
        reasoning += "Based on severity, confidence, and code pattern analysis."
        
        return ClassificationResult(
            is_true_positive=is_true_positive,
            probability=probability,
            confidence=confidence_score,
            reasoning=reasoning,
            feature_importance={}
        )
    
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        validation_split: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the classifier on labeled data.
        
        Args:
            X: Feature matrix (N, features)
            y: Labels (N,) - 1 for true positive, 0 for false positive
            validation_split: Fraction of data to use for validation
            
        Returns:
            Dictionary with training metrics
        """
        if not XGBOOST_AVAILABLE:
            raise ImportError("XGBoost is required for training")
        
        # Split data
        n_samples = len(X)
        n_val = int(n_samples * validation_split)
        indices = np.random.permutation(n_samples)
        
        X_train, X_val = X[indices[n_val:]], X[indices[:n_val]]
        y_train, y_val = y[indices[n_val:]], y[indices[:n_val]]
        
        # Train model
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False
        )
        
        # Evaluate
        train_acc = float(self.model.score(X_train, y_train))
        val_acc = float(self.model.score(X_val, y_val))
        
        # Get predictions for more metrics
        y_pred_val = self.model.predict(X_val)
        y_prob_val = self.model.predict_proba(X_val)[:, 1]
        
        # Calculate precision and recall
        tp = np.sum((y_pred_val == 1) & (y_val == 1))
        fp = np.sum((y_pred_val == 1) & (y_val == 0))
        fn = np.sum((y_pred_val == 0) & (y_val == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "train_accuracy": train_acc,
            "val_accuracy": val_acc,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "n_train": len(X_train),
            "n_val": len(X_val)
        }
    
    def save_model(self, path: str):
        """Save trained model to file."""
        if self.model is None:
            raise ValueError("No model to save")
        
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_names': self.feature_names
            }, f)
    
    def load_model(self, path: str):
        """Load trained model from file."""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.feature_names = data.get('feature_names', [])


# Global classifier instance
_global_classifier: Optional[VulnerabilityClassifier] = None


def get_classifier() -> VulnerabilityClassifier:
    """
    Get the global VulnerabilityClassifier instance.
    
    Returns:
        Singleton VulnerabilityClassifier instance
    """
    global _global_classifier
    
    if _global_classifier is None:
        # Try to load pre-trained model
        model_dir = Path.home() / ".cache" / "cai" / "models"
        model_path = model_dir / "vulnerability_classifier.pkl"
        
        if model_path.exists():
            _global_classifier = VulnerabilityClassifier(str(model_path))
        else:
            _global_classifier = VulnerabilityClassifier()
    
    return _global_classifier


__all__ = [
    'VulnerabilityClassifier',
    'ClassificationResult',
    'get_classifier',
]
