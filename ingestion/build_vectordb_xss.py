"""Vector database builder for XSS payloads with advanced features."""

import json
import os
import sys
import logging
import hashlib
import time
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from langchain.vectorstores import Chroma
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

from utils.logger import setup_logger

# Configure logging
logger = setup_logger(__name__)

@dataclass
class BuildConfig:
    """Configuration for vector database build"""
    chunks_path: str = "data_processed/xss_chunks.json"
    db_dir: str = "vectordb/xss/"
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    batch_size: int = 100
    max_workers: int = 4
    chunk_size: int = 512
    chunk_overlap: int = 50
    validate_data: bool = True
    backup_existing: bool = True
    compute_stats: bool = True

@dataclass
class BuildStats:
    """Statistics about the build process"""
    total_chunks: int = 0
    valid_chunks: int = 0
    invalid_chunks: int = 0
    duplicate_chunks: int = 0
    total_tokens: int = 0
    avg_chunk_size: float = 0.0
    build_time: float = 0.0
    errors: List[str] = None

class VectorDBBuilder:
    """Advanced vector database builder with validation and monitoring"""
    
    def __init__(self, config: Optional[BuildConfig] = None):
        self.config = config or BuildConfig()
        self.stats = BuildStats(errors=[])
        self._setup_paths()
        self._initialize_embedding_model()
        
    def _setup_paths(self) -> None:
        """Setup and validate paths"""
        try:
            # Convert to Path objects
            self.chunks_path = Path(self.config.chunks_path)
            self.db_dir = Path(self.config.db_dir)
            
            # Ensure chunks file exists
            if not self.chunks_path.exists():
                raise FileNotFoundError(f"Chunks file not found: {self.chunks_path}")
                
            # Create DB directory if needed
            self.db_dir.mkdir(parents=True, exist_ok=True)
            
            # Setup backup directory if enabled
            if self.config.backup_existing and self.db_dir.exists():
                self._backup_existing_db()
                
        except Exception as e:
            logger.error(f"Path setup failed: {str(e)}")
            raise
            
    def _initialize_embedding_model(self) -> None:
        """Initialize the embedding model"""
        try:
            logger.info(f"Initializing embedding model: {self.config.model_name}")
            self.embedding_model = HuggingFaceEmbeddings(
                model_name=self.config.model_name
            )
        except Exception as e:
            logger.error(f"Model initialization failed: {str(e)}")
            raise
            
    def _backup_existing_db(self) -> None:
        """Backup existing vector database"""
        try:
            if self.db_dir.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_dir = self.db_dir.parent / f"{self.db_dir.name}_backup_{timestamp}"
                
                logger.info(f"Backing up existing DB to: {backup_dir}")
                os.system(f"cp -r {self.db_dir} {backup_dir}")
                
        except Exception as e:
            logger.warning(f"Backup failed: {str(e)}")
            
    def _load_chunks(self) -> List[Dict[str, Any]]:
        """Load and validate chunks from file"""
        try:
            logger.info(f"Loading chunks from: {self.chunks_path}")
            with open(self.chunks_path, "r", encoding="utf-8") as f:
                chunks = json.load(f)
                
            if not isinstance(chunks, list):
                raise ValueError("Chunks must be a list")
                
            return chunks
            
        except Exception as e:
            logger.error(f"Failed to load chunks: {str(e)}")
            raise
            
    def _validate_chunk(self, chunk: Dict[str, Any]) -> bool:
        """Validate individual chunk structure"""
        required_fields = {"content", "metadata"}
        
        # Check required fields
        if not all(field in chunk for field in required_fields):
            return False
            
        # Validate content
        if not isinstance(chunk["content"], str) or not chunk["content"].strip():
            return False
            
        # Validate metadata
        if not isinstance(chunk["metadata"], dict):
            return False
            
        return True
        
    def _process_chunk(self, chunk: Dict[str, Any]) -> Optional[Document]:
        """Process individual chunk into Document"""
        try:
            if not self.config.validate_data or self._validate_chunk(chunk):
                return Document(
                    page_content=chunk["content"],
                    metadata=chunk["metadata"]
                )
            else:
                self.stats.invalid_chunks += 1
                return None
                
        except Exception as e:
            logger.warning(f"Chunk processing failed: {str(e)}")
            self.stats.errors.append(str(e))
            return None
            
    def _compute_chunk_hash(self, content: str) -> str:
        """Compute hash of chunk content"""
        return hashlib.sha256(content.encode()).hexdigest()
        
    def _deduplicate_chunks(self, docs: List[Document]) -> List[Document]:
        """Remove duplicate chunks"""
        unique_docs = {}
        for doc in docs:
            content_hash = self._compute_chunk_hash(doc.page_content)
            if content_hash not in unique_docs:
                unique_docs[content_hash] = doc
            else:
                self.stats.duplicate_chunks += 1
                
        return list(unique_docs.values())
        
    def _update_stats(self, docs: List[Document], build_time: float) -> None:
        """Update build statistics"""
        if self.config.compute_stats:
            self.stats.total_chunks = len(docs)
            self.stats.valid_chunks = len([d for d in docs if d is not None])
            self.stats.total_tokens = sum(len(d.page_content.split()) for d in docs)
            self.stats.avg_chunk_size = sum(len(d.page_content) for d in docs) / len(docs)
            self.stats.build_time = build_time
            
    def _log_stats(self) -> None:
        """Log build statistics"""
        logger.info("Build Statistics:")
        logger.info(f"- Total Chunks: {self.stats.total_chunks}")
        logger.info(f"- Valid Chunks: {self.stats.valid_chunks}")
        logger.info(f"- Invalid Chunks: {self.stats.invalid_chunks}")
        logger.info(f"- Duplicate Chunks: {self.stats.duplicate_chunks}")
        logger.info(f"- Total Tokens: {self.stats.total_tokens}")
        logger.info(f"- Avg Chunk Size: {self.stats.avg_chunk_size:.2f}")
        logger.info(f"- Build Time: {self.stats.build_time:.2f}s")
        if self.stats.errors:
            logger.warning(f"- Errors: {len(self.stats.errors)}")
            for error in self.stats.errors[:5]:  # Show first 5 errors
                logger.warning(f"  - {error}")
                
    def build(self) -> None:
        """Build the vector database"""
        start_time = time.time()
        
        try:
            # Load chunks
            chunks = self._load_chunks()
            logger.info(f"Loaded {len(chunks)} chunks")
            
            # Process chunks in parallel
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                docs = list(tqdm(
                    executor.map(self._process_chunk, chunks),
                    total=len(chunks),
                    desc="Processing chunks"
                ))
            
            # Remove None values from failed processing
            docs = [d for d in docs if d is not None]
            
            # Deduplicate if needed
            if self.config.validate_data:
                docs = self._deduplicate_chunks(docs)
                
            # Build database in batches
            logger.info("Building vector database...")
            db = None
            for i in tqdm(range(0, len(docs), self.config.batch_size)):
                batch = docs[i:i + self.config.batch_size]
                if db is None:
                    db = Chroma.from_documents(
                        documents=batch,
                        embedding=self.embedding_model,
                        persist_directory=str(self.db_dir)
                    )
                else:
                    db.add_documents(batch)
                    
            # Persist final database
            logger.info("Persisting database...")
            db.persist()
            
            # Update and log statistics
            build_time = time.time() - start_time
            self._update_stats(docs, build_time)
            self._log_stats()
            
            logger.info(f"[✓] Successfully built vector database at {self.db_dir}")
            
        except Exception as e:
            logger.error(f"Database build failed: {str(e)}")
            raise

if __name__ == "__main__":
    try:
        # Create builder with default or custom config
        config = BuildConfig()
        builder = VectorDBBuilder(config)
        
        # Build database
        builder.build()
        
    except Exception as e:
        logger.error(f"Build failed: {str(e)}")
        sys.exit(1)
