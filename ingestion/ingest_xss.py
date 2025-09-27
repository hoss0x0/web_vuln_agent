"""XSS knowledge ingestion with parallel processing and validation."""

import os
import json
import time
import logging
import re
from uuid import uuid4
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict

from ingestion.helpers import (
    clean_text, chunk_text, analyze_text, ChunkConfig, process_text_parallel
)
from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class XSSIngestionConfig:
    """Configuration for XSS ingestion"""
    raw_dir: str = "data_raw/xss/"
    out_path: str = "data_processed/xss_chunks.json"
    max_workers: int = 4
    backup_existing: bool = True
    validate_content: bool = True
    detect_payloads: bool = True  # XSS-specific: detect potential payloads
    chunk_config: ChunkConfig = ChunkConfig(
        chunk_size=500,
        overlap=50,
        respect_sentences=True,
        preserve_code_blocks=True
    )

@dataclass
class XSSIngestionStats:
    """Statistics for XSS ingestion"""
    start_time: float
    end_time: float
    total_files: int = 0
    processed_files: int = 0
    total_chunks: int = 0
    invalid_chunks: int = 0
    payload_chunks: int = 0  # XSS-specific: chunks containing payloads
    errors: List[str] = None

    def __post_init__(self):
        self.errors = []

    def to_dict(self) -> Dict:
        """Convert stats to dictionary"""
        return {
            "duration_seconds": round(self.end_time - self.start_time, 2),
            "total_files": self.total_files,
            "processed_files": self.processed_files,
            "total_chunks": self.total_chunks,
            "invalid_chunks": self.invalid_chunks,
            "payload_chunks": self.payload_chunks,
            "success_rate": round(
                (self.processed_files / self.total_files * 100)
                if self.total_files else 0,
                2
            ),
            "errors": self.errors
        }

class XSSIngester:
    """XSS data ingester with parallel processing"""
    
    # XSS-specific patterns for payload detection
    PAYLOAD_PATTERNS: Set[str] = {
        r'<script[^>]*>.*?</script>',
        r'javascript:.*',
        r'onerror=.*',
        r'onload=.*',
        r'onclick=.*',
        r'alert\(.*?\)',
        r'eval\(.*?\)',
        r'document\.cookie',
        r'<img[^>]+src=',
        r'data:.*?base64',
    }
    
    def __init__(self, config: Optional[XSSIngestionConfig] = None):
        self.config = config or XSSIngestionConfig()
        self.stats = XSSIngestionStats(start_time=time.time(), end_time=0)
        self._validate_paths()
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for payload detection"""
        self.payload_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.PAYLOAD_PATTERNS
        ]

    def _validate_paths(self) -> None:
        """Validate input/output paths"""
        if not os.path.exists(self.config.raw_dir):
            raise FileNotFoundError(f"Raw data directory not found: {self.config.raw_dir}")
        
        # Create output directory if needed
        os.makedirs(os.path.dirname(self.config.out_path), exist_ok=True)

    def _backup_existing(self) -> None:
        """Backup existing output file"""
        if not self.config.backup_existing:
            return

        out_path = Path(self.config.out_path)
        if out_path.exists():
            backup_path = out_path.with_suffix(f".json.bak")
            out_path.rename(backup_path)
            logger.info(f"Backed up existing file to {backup_path}")

    def _detect_payloads(self, content: str) -> List[str]:
        """Detect potential XSS payloads in content"""
        if not self.config.detect_payloads:
            return []

        payloads = []
        for pattern in self.payload_patterns:
            matches = pattern.findall(content)
            payloads.extend(matches)
        return list(set(payloads))  # Remove duplicates

    def _validate_chunk(self, chunk: Dict) -> bool:
        """Validate chunk content and structure"""
        try:
            required_keys = {"chunk_id", "content", "metadata"}
            if not all(key in chunk for key in required_keys):
                return False

            content = chunk["content"]
            if not content or len(content) < 10:  # Minimum content length
                return False

            # Analyze text quality
            stats = analyze_text(content)
            if not stats:
                return False

            # Check for XSS payloads
            payloads = self._detect_payloads(content)
            if payloads:
                self.stats.payload_chunks += 1
                chunk["metadata"]["payloads"] = payloads

            return True

        except Exception as e:
            self.stats.errors.append(f"Chunk validation failed: {str(e)}")
            return False

    def _process_file(self, file_path: str) -> List[Dict]:
        """Process single file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = f.read()
            
            # Clean and chunk text
            cleaned = clean_text(raw)
            split_chunks = chunk_text(cleaned, self.config.chunk_config)
            
            # Create chunk objects
            chunks = []
            for chunk in split_chunks:
                chunk_obj = {
                    "chunk_id": f"xss_{uuid4().hex[:8]}",
                    "content": chunk,
                    "metadata": {
                        "vulnerability": "xss",
                        "source_file": os.path.basename(file_path),
                        "file_path": file_path,
                        "timestamp": time.time()
                    }
                }
                
                if not self.config.validate_content or self._validate_chunk(chunk_obj):
                    chunks.append(chunk_obj)
                else:
                    self.stats.invalid_chunks += 1

            self.stats.processed_files += 1
            return chunks

        except Exception as e:
            self.stats.errors.append(f"Failed to process {file_path}: {str(e)}")
            logger.error(f"Error processing {file_path}: {str(e)}")
            return []

    def ingest(self) -> bool:
        """Run ingestion process"""
        try:
            logger.info("Starting XSS data ingestion...")
            
            # Get input files
            files = [
                os.path.join(self.config.raw_dir, f)
                for f in os.listdir(self.config.raw_dir)
                if f.endswith((".txt", ".md"))
            ]
            self.stats.total_files = len(files)

            if not files:
                logger.warning("No input files found")
                return False

            # Backup existing output
            self._backup_existing()

            # Process files in parallel
            chunks = []
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                file_chunks = list(executor.map(self._process_file, files))
                chunks = [chunk for sublist in file_chunks for chunk in sublist]

            self.stats.total_chunks = len(chunks)

            # Save results
            with open(self.config.out_path, "w", encoding="utf-8") as f:
                json.dump(chunks, f, indent=2, ensure_ascii=False)

            # Finalize stats
            self.stats.end_time = time.time()
            stats_dict = self.stats.to_dict()
            
            logger.info(
                f"XSS ingestion completed:\n"
                f"- Processed {stats_dict['processed_files']}/{stats_dict['total_files']} files\n"
                f"- Generated {stats_dict['total_chunks']} valid chunks\n"
                f"- Found {stats_dict['invalid_chunks']} invalid chunks\n"
                f"- Detected {stats_dict['payload_chunks']} chunks with XSS payloads\n"
                f"- Success rate: {stats_dict['success_rate']}%\n"
                f"- Duration: {stats_dict['duration_seconds']}s"
            )

            if self.stats.errors:
                logger.warning(f"Encountered {len(self.stats.errors)} errors:")
                for error in self.stats.errors[:5]:  # Show first 5 errors
                    logger.warning(f"- {error}")

            return self.stats.processed_files > 0 and not self.stats.errors

        except Exception as e:
            logger.error(f"Ingestion failed: {str(e)}")
            return False

def main():
    """Main entry point"""
    config = XSSIngestionConfig()
    ingester = XSSIngester(config)
    success = ingester.ingest()
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
