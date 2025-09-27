"""Advanced vector database management with caching, batching, and hybrid search capabilities."""

import os
import json
import time
import hashlib
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from langchain.vectorstores import Chroma
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.docstore.document import Document
from langchain.schema import BaseRetriever
from langchain.retrievers import BM25Retriever, EnsembleRetriever

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class VectorDBConfig:
    """Configuration for vector database."""
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    device: str = "cpu"
    normalize_embeddings: bool = True
    cache_size: int = 1000
    batch_size: int = 32
    max_threads: int = 4
    similarity_top_k: int = 3
    mmr_top_k: int = 6
    mmr_diversity_bias: float = 0.3
    hybrid_search: bool = True
    bm25_weight: float = 0.3
    cache_dir: str = ".cache/embeddings"
    persist_directory: Optional[str] = None

class VectorDBManager:
    """Advanced vector database manager with enhanced features."""
    
    def __init__(self, config: Optional[VectorDBConfig] = None):
        """Initialize vector database manager with configuration."""
        self.config = config or VectorDBConfig()
        self._setup_cache_directory()
        self.embedding_model = self._initialize_embeddings()
        self.vectordb = None
        self.bm25_retriever = None
        self.ensemble_retriever = None
        
    def _setup_cache_directory(self) -> None:
        """Create cache directory with proper permissions."""
        try:
            cache_dir = Path(self.config.cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.chmod(0o750)  # Secure permissions
        except Exception as e:
            logger.error(f"Failed to create cache directory: {str(e)}")
            raise

    def _initialize_embeddings(self) -> HuggingFaceEmbeddings:
        """Initialize embedding model with caching."""
        try:
            return HuggingFaceEmbeddings(
                model_name=self.config.model_name,
                cache_folder=self.config.cache_dir,
                model_kwargs={
                    "device": self.config.device
                },
                encode_kwargs={
                    "normalize_embeddings": self.config.normalize_embeddings,
                    "batch_size": self.config.batch_size
                }
            )
        except Exception as e:
            logger.error(f"Failed to initialize embeddings: {str(e)}")
            raise

    def _setup_retrievers(self, documents: List[Document]) -> None:
        """Setup BM25 and ensemble retrievers for hybrid search."""
        try:
            if self.config.hybrid_search:
                self.bm25_retriever = BM25Retriever.from_documents(documents)
                self.ensemble_retriever = EnsembleRetriever(
                    retrievers=[
                        self.vectordb.as_retriever(
                            search_kwargs={"k": self.config.similarity_top_k}
                        ),
                        self.bm25_retriever
                    ],
                    weights=[1 - self.config.bm25_weight, self.config.bm25_weight]
                )
        except Exception as e:
            logger.error(f"Failed to setup retrievers: {str(e)}")
            self.config.hybrid_search = False

    @staticmethod
    def _generate_cache_key(query: str, **kwargs) -> str:
        """Generate cache key for query results."""
        key_data = f"{query}_{json.dumps(kwargs, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def load_vectordb(self, path: Union[str, Path]) -> None:
        """Load or create vector database."""
        try:
            self.config.persist_directory = str(path)
            self.vectordb = Chroma(
                persist_directory=self.config.persist_directory,
                embedding_function=self.embedding_model
            )
            logger.info(f"Vector database loaded from {path}")
            
            # Setup hybrid search if enabled
            if self.config.hybrid_search:
                documents = [
                    Document(page_content=doc.page_content, metadata=doc.metadata)
                    for doc in self.vectordb.get()
                ]
                self._setup_retrievers(documents)
                
        except Exception as e:
            logger.error(f"Failed to load vector database: {str(e)}")
            raise

    @lru_cache(maxsize=1000)
    def _cached_query(
        self,
        cache_key: str,
        query: str,
        search_type: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Cached query execution."""
        if search_type == "similarity":
            results = self.vectordb.similarity_search(query, **kwargs)
        elif search_type == "mmr":
            results = self.vectordb.max_marginal_relevance_search(
                query,
                k=kwargs.get("k", self.config.mmr_top_k),
                fetch_k=kwargs.get("fetch_k", self.config.mmr_top_k * 2),
                lambda_mult=kwargs.get("lambda_mult", self.config.mmr_diversity_bias)
            )
        elif search_type == "hybrid":
            results = self.ensemble_retriever.get_relevant_documents(query)
        else:
            raise ValueError(f"Unknown search type: {search_type}")
            
        return [{"content": r.page_content, "metadata": r.metadata} for r in results]

    def query_vectordb(
        self,
        query: str,
        search_type: str = "similarity",
        top_k: Optional[int] = None,
        threshold: Optional[float] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Query vector database with multiple search strategies.
        
        Args:
            query: Search query
            search_type: Type of search ("similarity", "mmr", or "hybrid")
            top_k: Number of results to return
            threshold: Minimum similarity score threshold
            **kwargs: Additional search parameters
            
        Returns:
            List of results with content and metadata
        """
        if not self.vectordb:
            raise ValueError("Vector database not loaded. Call load_vectordb first.")
            
        try:
            # Update kwargs with defaults
            kwargs["k"] = top_k or self.config.similarity_top_k
            
            # Generate cache key
            cache_key = self._generate_cache_key(query, search_type=search_type, **kwargs)
            
            # Execute cached query
            results = self._cached_query(cache_key, query, search_type, **kwargs)
            
            # Apply threshold filtering if specified
            if threshold is not None:
                results = [
                    r for r in results
                    if self.vectordb.similarity_search_with_score(
                        r["content"], k=1
                    )[0][1] >= threshold
                ]
            
            logger.debug(
                f"Query executed successfully: {search_type}, "
                f"results: {len(results)}, cache_key: {cache_key}"
            )
            return results
            
        except Exception as e:
            logger.error(f"Query failed: {str(e)}")
            raise

    def batch_query(
        self,
        queries: List[str],
        **kwargs
    ) -> List[List[Dict[str, Any]]]:
        """Execute multiple queries in parallel."""
        try:
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                return list(executor.map(
                    lambda q: self.query_vectordb(q, **kwargs),
                    queries
                ))
        except Exception as e:
            logger.error(f"Batch query failed: {str(e)}")
            raise

# Initialize global vector database manager
vectordb_manager = VectorDBManager()
