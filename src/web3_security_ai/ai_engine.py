#!/usr/bin/env python3

"""
AI/ML Engine for the Web3 Security Audit System.
Integrates SmartBERT embeddings and SmartIntentNN for vulnerability detection.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import numpy as np
import logging
from enum import Enum

from .base_agent import BaseAgent, AgentConfig, AgentType, AgentRole


class EmbeddingType(Enum):
    """Types of embeddings supported."""
    SMART_BERT = "smart_bert"
    WORD_EMBEDDING = "word_embedding"
    CONTEXTUAL = "contextual"


class IntentClassification(Enum):
    """Classification of detected intents."""
    MALICIOUS = "malicious"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class EmbeddingResult:
    """Result of embedding computation."""
    text: str
    embedding: np.ndarray
    embedding_type: EmbeddingType
    confidence: float


@dataclass
class IntentDetectionResult:
    """Result of intent detection."""
    text: str
    classification: IntentClassification
    confidence_scores: Dict[IntentClassification, float]
    raw_output: Any


class SmartBERTEmbeddings:
    """Simulated SmartBERT embeddings engine."""
    
    def __init__(self):
        self.embedding_dimension = 768
        self.logger = logging.getLogger(__name__)
        
    def encode(self, text: str) -> np.ndarray:
        """Generate 768-dimensional embedding for text.
        
        Args:
            text: Text to encode
            
        Returns:
            768-dimensional numpy array
        """
        # In a real implementation, this would use a pre-trained BERT model
        # For simulation, we create a pseudo-random embedding
        np.random.seed(hash(text) % (2**32))
        return np.random.rand(self.embedding_dimension).astype(np.float32)
    
    def compute_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Compute cosine similarity between two embeddings.
        
        Args:
            emb1: First embedding
            emb2: Second embedding
            
        Returns:
            Cosine similarity score (0-1)
        """
        dot_product = np.dot(emb1, emb2)
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
            
        return dot_product / (norm1 * norm2)


class SmartIntentNN:
    """Simulated SmartIntentNN for malicious intent detection."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def classify_intent(self, text: str, embedding: np.ndarray) -> IntentDetectionResult:
        """Classify the intent of text using neural network.
        
        Args:
            text: Text to analyze
            embedding: Pre-computed embedding
            
        Returns:
            Intent classification result
        """
        # Simulated intent classification
        # In a real implementation, this would use a trained neural network
        
        # Compute some heuristics for intent classification
        text_lower = text.lower()
        malicious_indicators = [
            'revert', 'transfer', 'send', 'call', 'delegatecall', 'selfdestruct',
            'unchecked', 'dangerous', 'unsafe', 'bug', 'exploit', 'attack'
        ]
        
        malicious_count = sum(1 for indicator in malicious_indicators if indicator in text_lower)
        benign_count = sum(1 for word in ['safe', 'secure', 'verified', 'approved', 'normal'] 
                          if word in text_lower)
        
        # Simple heuristic-based classification
        if malicious_count > benign_count:
            classification = IntentClassification.MALICIOUS
        elif benign_count > malicious_count:
            classification = IntentClassification.BENIGN
        elif malicious_count == benign_count and malicious_count > 0:
            classification = IntentClassification.SUSPICIOUS
        else:
            classification = IntentClassification.UNKNOWN
            
        # Compute confidence scores
        confidence_scores = {
            IntentClassification.MALICIOUS: max(0.0, min(1.0, malicious_count / 10.0)),
            IntentClassification.BENIGN: max(0.0, min(1.0, benign_count / 10.0)),
            IntentClassification.SUSPICIOUS: 0.5 if malicious_count == benign_count and malicious_count > 0 else 0.0,
            IntentClassification.UNKNOWN: 0.0 if classification != IntentClassification.UNKNOWN else 1.0
        }
        
        # Normalize confidence scores
        total = sum(confidence_scores.values())
        if total > 0:
            for key in confidence_scores:
                confidence_scores[key] /= total
                
        return IntentDetectionResult(
            text=text,
            classification=classification,
            confidence_scores=confidence_scores,
            raw_output={
                'malicious_count': malicious_count,
                'benign_count': benign_count,
                'embedding_shape': embedding.shape if embedding is not None else 'none'
            }
        )


class AIEngine(BaseAgent):
    """AI/ML Engine integrating SmartBERT and SmartIntentNN."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.smart_bert = SmartBERTEmbeddings()
        self.smart_intent_nn = SmartIntentNN()
        
        # Cache for embeddings
        self.embedding_cache = {}
        
    async def initialize(self) -> bool:
        """Initialize the AI engine."""
        self.is_active = True
        self.logger.info(f"AI Engine {self.name} initialized")
        return True
    
    async def cleanup(self) -> None:
        """Clean up the AI engine."""
        self.is_active = False
        self.logger.info(f"AI Engine {self.name} cleaned up")
    
    async def execute_task(self, task: str, **kwargs) -> Dict[str, Any]:
        """Execute an AI/ML task.
        
        Args:
            task: Description of task to execute
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with execution results
        """
        try:
            # Parse the task
            task_data = json.loads(task) if isinstance(task, str) else task
            
            # Extract parameters
            task_type = task_data.get("type", "embedding")
            text = task_data.get("text", "")
            comparison_text = task_data.get("comparison_text", None)
            
            if task_type == "embedding":
                result = await self._compute_embedding(text, **kwargs)
            elif task_type == "intent_classification":
                result = await self._classify_intent(text, **kwargs)
            elif task_type == "similarity":
                result = await self._compute_similarity(text, comparison_text, **kwargs)
            else:
                raise ValueError(f"Unsupported task type: {task_type}")
            
            return {
                "success": True,
                "result": result,
                "message": f"AI task {task_type} completed successfully"
            }
            
        except Exception as e:
            self.logger.error(f"Error in AI task: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "message": f"AI task failed: {str(e)}"
            }
    
    async def _compute_embedding(self, text: str, **kwargs) -> Dict[str, Any]:
        """Compute embedding for text.
        
        Args:
            text: Text to embed
            **kwargs: Additional parameters
            
        Returns:
            Embedding result
        """
        # Check cache first
        cache_key = f"embedding_{hash(text)}"
        if cache_key in self.embedding_cache:
            self.logger.info(f"Using cached embedding for text")
            return self.embedding_cache[cache_key]
        
        # Compute embedding
        embedding = self.smart_bert.encode(text)
        
        # Cache result
        result = {
            "text": text,
            "embedding": embedding.tolist(),
            "embedding_type": EmbeddingType.SMART_BERT.value,
            "embedding_dimension": self.smart_bert.embedding_dimension,
            "confidence": 0.95  # Simulated confidence
        }
        
        self.embedding_cache[cache_key] = result
        return result
    
    async def _classify_intent(self, text: str, **kwargs) -> Dict[str, Any]:
        """Classify the intent of text.
        
        Args:
            text: Text to analyze
            **kwargs: Additional parameters
            
        Returns:
            Intent classification result
        """
        # First get embedding
        embedding_result = await self._compute_embedding(text)
        embedding = np.array(embedding_result["embedding"])
        
        # Then classify intent
        intent_result = self.smart_intent_nn.classify_intent(text, embedding)
        
        return {
            "text": text,
            "classification": intent_result.classification.value,
            "confidence_scores": intent_result.confidence_scores,
            "raw_output": intent_result.raw_output
        }
    
    async def _compute_similarity(self, text1: str, text2: str, **kwargs) -> Dict[str, Any]:
        """Compute similarity between two texts.
        
        Args:
            text1: First text
            text2: Second text
            **kwargs: Additional parameters
            
        Returns:
            Similarity result
        """
        # Get embeddings for both texts
        embedding1_result = await self._compute_embedding(text1)
        embedding2_result = await self._compute_embedding(text2)
        
        embedding1 = np.array(embedding1_result["embedding"])
        embedding2 = np.array(embedding2_result["embedding"])
        
        # Compute similarity
        similarity = self.smart_bert.compute_similarity(embedding1, embedding2)
        
        return {
            "text1": text1,
            "text2": text2,
            "similarity": similarity,
            "cosine_similarity": similarity
        }
    
    def clear_cache(self) -> None:
        """Clear the embedding cache."""
        self.embedding_cache.clear()
        self.logger.info("AI engine embedding cache cleared")
    
    def get_confidence_scoring(self, findings: List[Dict[str, Any]], 
                             ai_results: Dict[str, Any]) -> float:
        """Calculate confidence score for combined analysis.
        
        Args:
            findings: Traditional security findings
            ai_results: AI/ML analysis results
            
        Returns:
            Weighted confidence score (0-1)
        """
        # Calculate base confidence from traditional findings
        base_confidence = len(findings) * 0.1  # Assume 10% per finding
        
        # Adjust based on AI results
        ai_confidence = 0.0
        if ai_results and "confidence_scores" in ai_results:
            # Get highest confidence from AI classification
            scores = ai_results["confidence_scores"]
            ai_confidence = max(scores.values()) if scores else 0.0
        
        # Apply weighted formula (simplified)
        combined_confidence = (base_confidence * 0.6 + ai_confidence * 0.4)
        return min(1.0, combined_confidence)
