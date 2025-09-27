"""Enhanced vector store retriever with advanced features and caching."""

import os
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Union, Any
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
import numpy as np

from langchain.vectorstores import Chroma
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.docstore.document import Document

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class RetrieverConfig:
    """Configuration for vector store retriever"""
    db_dir: str = "vectordb/xss/"
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    cache_dir: str = "models/cache"
    similarity_threshold: float = 0.7
    max_chunk_size: int = 512
    cross_encoder_rerank: bool = True
    use_cache: bool = True
    cache_size: int = 1000
    pooling_strategy: str = "mean"
    normalize_embeddings: bool = True
    hybrid_search: bool = True

class VectorStoreManager:
    """Enhanced vector store manager with advanced features"""
    
    def __init__(self, config: Optional[RetrieverConfig] = None):
        """Initialize vector store manager"""
        self.config = config or self._load_config()
        self._setup_paths()
        self.embedding_model = None
        self.vector_store = None
        self.query_cache = {}

    def _load_config(self) -> RetrieverConfig:
        """Load configuration from YAML file"""
        try:
            config_path = Path("config/retriever_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                config_dict = yaml.safe_load(f)
                return RetrieverConfig(**config_dict)
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {str(e)}")
            return RetrieverConfig()

    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        config_dict = {
            "db_dir": "vectordb/xss/",
            "model_name": "sentence-transformers/all-MiniLM-L6-v2",
            "cache_dir": "models/cache",
            "similarity_threshold": 0.7,
            "max_chunk_size": 512,
            "cross_encoder_rerank": True,
            "use_cache": True,
            "cache_size": 1000,
            "pooling_strategy": "mean",
            "normalize_embeddings": True,
            "hybrid_search": True
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False)

    def _setup_paths(self) -> None:
        """Setup and validate paths"""
        # Ensure DB directory exists
        db_path = Path(self.config.db_dir)
        db_path.mkdir(parents=True, exist_ok=True)
        
        # Setup cache directory
        cache_path = Path(self.config.cache_dir)
        cache_path.mkdir(parents=True, exist_ok=True)
        os.environ["TRANSFORMERS_CACHE"] = str(cache_path)

    @lru_cache(maxsize=1)
    def get_embedding_model(self) -> HuggingFaceEmbeddings:
        """Get or initialize embedding model"""
        if self.embedding_model is None:
            try:
                self.embedding_model = HuggingFaceEmbeddings(
                    model_name=self.config.model_name,
                    cache_folder=self.config.cache_dir,
                    encode_kwargs={
                        "normalize_embeddings": self.config.normalize_embeddings
                    }
                )
                logger.info(f"Initialized embedding model: {self.config.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize embedding model: {str(e)}")
                raise
        return self.embedding_model

    @lru_cache(maxsize=1)
    def get_vector_store(self) -> Chroma:
        """Get or initialize vector store"""
        if self.vector_store is None:
            try:
                embedding_model = self.get_embedding_model()
                self.vector_store = Chroma(
                    persist_directory=self.config.db_dir,
                    embedding_function=embedding_model
                )
                logger.info(f"Initialized vector store at: {self.config.db_dir}")
            except Exception as e:
                logger.error(f"Failed to initialize vector store: {str(e)}")
                raise
        return self.vector_store

    def _compute_query_hash(self, query: str, **kwargs) -> str:
        """Compute hash for query caching"""
        cache_key = f"{query}_{sorted(kwargs.items())}"
        return str(hash(cache_key))

    def _filter_results(
        self,
        results: List[Document],
        scores: List[float]
    ) -> List[Dict[str, Any]]:
        """Filter and format retrieval results"""
        filtered_results = []
        
        for doc, score in zip(results, scores):
            if score >= self.config.similarity_threshold:
                filtered_results.append({
                    "content": doc.page_content,
                    "metadata": {
                        **doc.metadata,
                        "relevance_score": round(float(score), 3),
                        "retrieved_at": datetime.utcnow().isoformat()
                    }
                })
                
        return filtered_results

    def _hybrid_search(
        self,
        query: str,
        top_k: int
    ) -> List[Dict[str, Any]]:
        """Perform hybrid semantic and keyword search"""
        # Semantic search
        vector_results = self.get_vector_store().similarity_search_with_score(
            query,
            k=top_k
        )
        
        # Keyword search (if available)
        try:
            keyword_results = self.get_vector_store().similarity_search_with_score(
                query,
                k=top_k,
                search_type="keyword"
            )
        except:
            keyword_results = []

        # Combine and deduplicate results
        all_results = vector_results + keyword_results
        seen_contents = set()
        unique_results = []
        
        for doc, score in all_results:
            if doc.page_content not in seen_contents:
                seen_contents.add(doc.page_content)
                unique_results.append((doc, score))

        # Sort by score and take top_k
        unique_results.sort(key=lambda x: x[1], reverse=True)
        return self._filter_results(
            [doc for doc, _ in unique_results[:top_k]],
            [score for _, score in unique_results[:top_k]]
        )

    def retrieve_chunks(
        self,
        query: str,
        top_k: int = 3,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Retrieve relevant chunks with advanced features"""
        try:
            # Check cache if enabled
            if self.config.use_cache:
                cache_key = self._compute_query_hash(query, top_k=top_k, **kwargs)
                if cache_key in self.query_cache:
                    logger.debug("Retrieved results from cache")
                    return self.query_cache[cache_key]

            # Perform retrieval
            if self.config.hybrid_search:
                results = self._hybrid_search(query, top_k)
            else:
                vector_results = self.get_vector_store().similarity_search_with_score(
                    query,
                    k=top_k,
                    **kwargs
                )
                results = self._filter_results(
                    [doc for doc, _ in vector_results],
                    [score for _, score in vector_results]
                )

            # Update cache if enabled
            if self.config.use_cache:
                if len(self.query_cache) >= self.config.cache_size:
                    # Remove oldest entry
                    self.query_cache.pop(next(iter(self.query_cache)))
                self.query_cache[cache_key] = results

            return results

        except Exception as e:
            logger.error(f"Retrieval failed: {str(e)}")
            return []

    def clear_cache(self) -> None:
        """Clear retrieval cache"""
        self.query_cache.clear()
        logger.info("Cleared retrieval cache")

# Initialize global vector store manager
vector_store_manager = VectorStoreManager()

def retrieve_chunks(
    query: str,
    top_k: int = 3,
    **kwargs
) -> List[Dict[str, Any]]:
    """Retrieve chunks using vector store manager"""
    return vector_store_manager.retrieve_chunks(query, top_k, **kwargs)
