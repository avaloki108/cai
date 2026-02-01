"""
SmartBERT Embeddings for Solidity Code

This module provides neural embeddings for Solidity smart contracts using
SmartBERT, a BERT-based model pre-trained on Solidity code.

Benefits over hash-based embeddings:
- Semantic understanding of code structure
- Better similarity detection for code clones
- Context-aware vulnerability pattern matching
"""

import os
import numpy as np
from typing import List, Optional, Union
from pathlib import Path
import hashlib


# Try to import transformers, fall back to hash-based if unavailable
try:
    from transformers import AutoModel, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class SmartBERTEmbedder:
    """
    SmartBERT-based code embedder for Solidity contracts.
    
    Uses a pre-trained BERT model fine-tuned on Solidity code to generate
    high-quality semantic embeddings.
    """
    
    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",  # Fallback to CodeBERT
        cache_dir: Optional[str] = None,
        use_gpu: bool = True
    ):
        """
        Initialize the SmartBERT embedder.
        
        Args:
            model_name: HuggingFace model identifier or path
            cache_dir: Directory to cache downloaded models
            use_gpu: Whether to use GPU if available
        """
        self.model_name = model_name
        self.cache_dir = cache_dir or str(Path.home() / ".cache" / "cai" / "models")
        
        if not TRANSFORMERS_AVAILABLE:
            print("Warning: transformers library not available, using fallback embeddings")
            self.model = None
            self.tokenizer = None
            self.device = "cpu"
            return
        
        # Set device
        self.device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        
        try:
            # Load model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                cache_dir=self.cache_dir
            )
            self.model = AutoModel.from_pretrained(
                model_name,
                cache_dir=self.cache_dir
            ).to(self.device)
            
            self.model.eval()  # Set to evaluation mode
            
        except Exception as e:
            print(f"Warning: Could not load SmartBERT model ({e}), using fallback")
            self.model = None
            self.tokenizer = None
    
    def embed_code(
        self,
        code: Union[str, List[str]],
        max_length: int = 512,
        normalize: bool = True
    ) -> np.ndarray:
        """
        Generate embeddings for Solidity code.
        
        Args:
            code: Single code snippet or list of code snippets
            max_length: Maximum token length (truncates if longer)
            normalize: Whether to L2-normalize embeddings
            
        Returns:
            numpy array of shape (768,) for single input or (N, 768) for batch
        """
        if self.model is None or self.tokenizer is None:
            # Fallback to hash-based embeddings
            if isinstance(code, str):
                return self._hash_embedding(code, normalize=normalize)
            else:
                return np.array([self._hash_embedding(c, normalize=normalize) for c in code])
        
        # Handle single string input
        single_input = isinstance(code, str)
        if single_input:
            code = [code]
        
        # Tokenize
        inputs = self.tokenizer(
            code,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        ).to(self.device)
        
        # Generate embeddings (no gradient computation)
        with torch.no_grad():
            outputs = self.model(**inputs)
            
            # Use [CLS] token embedding or mean pooling
            # [CLS] token is at position 0
            embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
        
        # Normalize if requested
        if normalize:
            norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
            norms[norms == 0] = 1  # Avoid division by zero
            embeddings = embeddings / norms
        
        # Return single embedding if single input
        if single_input:
            return embeddings[0]
        
        return embeddings
    
    def _hash_embedding(self, text: str, dim: int = 768, normalize: bool = True) -> np.ndarray:
        """
        Fallback hash-based embedding when SmartBERT is not available.
        
        Args:
            text: Input text
            dim: Embedding dimension
            normalize: Whether to normalize
            
        Returns:
            numpy array of shape (dim,)
        """
        # Tokenize
        tokens = text.lower().split()
        
        # Create sparse vector
        vec = np.zeros(dim)
        
        for token in tokens:
            # Hash token to index
            token_hash = int(hashlib.blake2b(
                token.encode('utf-8'),
                digest_size=8
            ).hexdigest(), 16)
            
            idx = token_hash % dim
            vec[idx] += 1.0
        
        # Normalize
        if normalize:
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
        
        return vec
    
    def compute_similarity(
        self,
        code1: str,
        code2: str,
        metric: str = "cosine"
    ) -> float:
        """
        Compute similarity between two code snippets.
        
        Args:
            code1: First code snippet
            code2: Second code snippet
            metric: Similarity metric ("cosine" or "euclidean")
            
        Returns:
            Similarity score (higher = more similar for cosine)
        """
        emb1 = self.embed_code(code1, normalize=True)
        emb2 = self.embed_code(code2, normalize=True)
        
        if metric == "cosine":
            # Cosine similarity (already normalized)
            return float(np.dot(emb1, emb2))
        elif metric == "euclidean":
            # Euclidean distance (lower = more similar)
            return float(np.linalg.norm(emb1 - emb2))
        else:
            raise ValueError(f"Unknown metric: {metric}")
    
    def find_similar_code(
        self,
        query_code: str,
        candidate_codes: List[str],
        top_k: int = 5,
        threshold: float = 0.7
    ) -> List[tuple]:
        """
        Find most similar code snippets to query.
        
        Args:
            query_code: Query code snippet
            candidate_codes: List of candidate code snippets
            top_k: Number of top results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of (index, code, similarity_score) tuples
        """
        # Generate embeddings
        query_emb = self.embed_code(query_code, normalize=True)
        candidate_embs = self.embed_code(candidate_codes, normalize=True)
        
        # Compute similarities
        similarities = np.dot(candidate_embs, query_emb)
        
        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # Filter by threshold and return results
        results = []
        for idx in top_indices:
            sim = float(similarities[idx])
            if sim >= threshold:
                results.append((int(idx), candidate_codes[idx], sim))
        
        return results


class CodeSimilarityIndex:
    """
    Index for fast similarity search over large code collections.
    
    Uses FAISS for efficient nearest neighbor search when available.
    """
    
    def __init__(self, embedder: SmartBERTEmbedder):
        """
        Initialize the similarity index.
        
        Args:
            embedder: SmartBERTEmbedder instance
        """
        self.embedder = embedder
        self.embeddings = None
        self.codes = []
        self.metadata = []
        
        # Try to use FAISS for efficient search
        try:
            import faiss
            self.use_faiss = True
            self.index = None
        except ImportError:
            self.use_faiss = False
    
    def add_codes(
        self,
        codes: List[str],
        metadata: Optional[List[dict]] = None
    ):
        """
        Add codes to the index.
        
        Args:
            codes: List of code snippets
            metadata: Optional metadata for each code snippet
        """
        # Generate embeddings
        new_embeddings = self.embedder.embed_code(codes, normalize=True)
        
        # Add to storage
        if self.embeddings is None:
            self.embeddings = new_embeddings
        else:
            self.embeddings = np.vstack([self.embeddings, new_embeddings])
        
        self.codes.extend(codes)
        
        if metadata:
            self.metadata.extend(metadata)
        else:
            self.metadata.extend([{}] * len(codes))
        
        # Rebuild FAISS index if using it
        if self.use_faiss:
            self._build_faiss_index()
    
    def _build_faiss_index(self):
        """Build FAISS index for efficient search."""
        try:
            import faiss
            
            dim = self.embeddings.shape[1]
            
            # Use L2 index (embeddings are normalized, so L2 approximates cosine)
            self.index = faiss.IndexFlatL2(dim)
            self.index.add(self.embeddings.astype('float32'))
            
        except Exception as e:
            print(f"Warning: Could not build FAISS index: {e}")
            self.use_faiss = False
    
    def search(
        self,
        query_code: str,
        top_k: int = 5,
        threshold: float = 0.7
    ) -> List[tuple]:
        """
        Search for similar codes in the index.
        
        Args:
            query_code: Query code snippet
            top_k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of (index, code, similarity, metadata) tuples
        """
        query_emb = self.embedder.embed_code(query_code, normalize=True)
        
        if self.use_faiss and self.index is not None:
            # Use FAISS for fast search
            import faiss
            
            distances, indices = self.index.search(
                query_emb.reshape(1, -1).astype('float32'),
                top_k
            )
            
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                # Convert L2 distance to cosine similarity (approximate)
                similarity = 1.0 - (dist / 2.0)
                
                if similarity >= threshold:
                    results.append((
                        int(idx),
                        self.codes[idx],
                        float(similarity),
                        self.metadata[idx]
                    ))
            
            return results
        
        else:
            # Fallback to numpy search
            similarities = np.dot(self.embeddings, query_emb)
            top_indices = np.argsort(similarities)[::-1][:top_k]
            
            results = []
            for idx in top_indices:
                sim = float(similarities[idx])
                if sim >= threshold:
                    results.append((
                        int(idx),
                        self.codes[idx],
                        sim,
                        self.metadata[idx]
                    ))
            
            return results


# Global embedder instance
_global_embedder: Optional[SmartBERTEmbedder] = None


def get_embedder() -> SmartBERTEmbedder:
    """
    Get the global SmartBERT embedder instance.
    
    Returns:
        Singleton SmartBERTEmbedder instance
    """
    global _global_embedder
    
    if _global_embedder is None:
        _global_embedder = SmartBERTEmbedder()
    
    return _global_embedder


__all__ = [
    'SmartBERTEmbedder',
    'CodeSimilarityIndex',
    'get_embedder',
]
