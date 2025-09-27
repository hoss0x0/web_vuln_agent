"""Advanced knowledge ingestion system with monitoring and validation."""

import subprocess
import sys
import time
import logging
import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class IngestionConfig:
    """Configuration for ingestion process"""
    parallel_ingestion: bool = True
    max_workers: int = 4
    validate_output: bool = True
    backup_existing: bool = True
    compute_stats: bool = True
    timeout: int = 3600  # 1 hour timeout
    retry_count: int = 3
    retry_delay: int = 5

@dataclass
class IngestionStats:
    """Statistics about ingestion process"""
    start_time: datetime
    end_time: datetime
    total_files: int
    successful_files: int
    failed_files: int
    total_records: int
    total_tokens: int
    errors: List[str]
    execution_time: float
    memory_usage: float

class KnowledgeIngester:
    """Advanced knowledge ingestion system"""
    
    def __init__(self, config: Optional[IngestionConfig] = None):
        self.config = config or IngestionConfig()
        self.stats = None
        self._setup_paths()
        
    def _setup_paths(self) -> None:
        """Setup and validate paths"""
        self.base_path = Path(__file__).parent
        self.ingest_scripts = {
            "xss": self.base_path / "ingest_xss.py",
            "sqli": self.base_path / "ingest_sqli.py"
        }
        
        # Validate script existence
        for name, path in self.ingest_scripts.items():
            if not path.exists():
                raise FileNotFoundError(f"Ingestion script not found: {path}")
                
    async def _run_ingestion(self, script_path: Path, type_name: str) -> bool:
        """Run individual ingestion script with monitoring"""
        start_time = time.time()
        success = False
        
        try:
            logger.info(f"Starting {type_name} ingestion...")
            
            # Create process
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                str(script_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Monitor process with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout
                )
                
                # Check process result
                if process.returncode == 0:
                    logger.info(f"{type_name} ingestion completed successfully")
                    success = True
                else:
                    error_msg = stderr.decode().strip()
                    logger.error(
                        f"{type_name} ingestion failed with code {process.returncode}: "
                        f"{error_msg}"
                    )
                    
            except asyncio.TimeoutError:
                logger.error(f"{type_name} ingestion timed out after {self.config.timeout}s")
                process.terminate()
                
        except Exception as e:
            logger.error(f"{type_name} ingestion failed: {str(e)}")
            
        duration = time.time() - start_time
        logger.info(f"{type_name} ingestion took {duration:.2f}s")
        
        return success
        
    async def _run_with_retry(self, script_path: Path, type_name: str) -> bool:
        """Run ingestion with retries"""
        for attempt in range(self.config.retry_count):
            if attempt > 0:
                logger.info(
                    f"Retrying {type_name} ingestion (attempt {attempt + 1}/"
                    f"{self.config.retry_count})"
                )
                await asyncio.sleep(self.config.retry_delay)
                
            if await self._run_ingestion(script_path, type_name):
                return True
                
        return False
        
    async def _validate_ingestion(self, type_name: str) -> bool:
        """Validate ingestion output"""
        try:
            # Check vector database existence
            db_path = Path(f"vectordb/{type_name}")
            if not db_path.exists():
                logger.error(f"Vector database not found for {type_name}")
                return False
                
            # Check for essential files
            required_files = {"chroma.sqlite3", "chroma.sqlite3-shm", "chroma.sqlite3-wal"}
            existing_files = {p.name for p in db_path.glob("*")}
            
            if not required_files.issubset(existing_files):
                missing = required_files - existing_files
                logger.error(f"Missing files for {type_name}: {missing}")
                return False
                
            # Additional validation could be added here
            
            return True
            
        except Exception as e:
            logger.error(f"Validation failed for {type_name}: {str(e)}")
            return False
            
    def _compute_stats(self) -> None:
        """Compute ingestion statistics"""
        if not self.config.compute_stats:
            return
            
        try:
            stats = {
                "databases": {},
                "total_size": 0,
                "total_files": 0
            }
            
            for type_name in self.ingest_scripts.keys():
                db_path = Path(f"vectordb/{type_name}")
                if db_path.exists():
                    size = sum(f.stat().st_size for f in db_path.rglob("*"))
                    files = len(list(db_path.rglob("*")))
                    stats["databases"][type_name] = {
                        "size_bytes": size,
                        "file_count": files
                    }
                    stats["total_size"] += size
                    stats["total_files"] += files
                    
            # Save stats
            stats_path = Path("vectordb/ingestion_stats.json")
            stats_path.write_text(json.dumps(stats, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to compute stats: {str(e)}")
            
    async def ingest_all(self) -> bool:
        """Run all ingestion processes"""
        start_time = datetime.utcnow()
        total_success = True
        
        try:
            logger.info("Starting knowledge ingestion...")
            
            # Backup existing databases if configured
            if self.config.backup_existing:
                self._backup_existing_dbs()
                
            # Run ingestion scripts
            if self.config.parallel_ingestion:
                # Run in parallel
                tasks = [
                    self._run_with_retry(script, name)
                    for name, script in self.ingest_scripts.items()
                ]
                results = await asyncio.gather(*tasks)
                success = all(results)
            else:
                # Run sequentially
                success = True
                for name, script in self.ingest_scripts.items():
                    if not await self._run_with_retry(script, name):
                        success = False
                        
            # Validate if configured
            if success and self.config.validate_output:
                validation_tasks = [
                    self._validate_ingestion(name)
                    for name in self.ingest_scripts.keys()
                ]
                validations = await asyncio.gather(*validation_tasks)
                success = all(validations)
                
            # Compute stats if configured
            if success and self.config.compute_stats:
                self._compute_stats()
                
            total_success = success
            
        except Exception as e:
            logger.error(f"Ingestion process failed: {str(e)}")
            total_success = False
            
        finally:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            if total_success:
                logger.info(f"[✓] All ingestion completed successfully in {duration:.2f}s")
            else:
                logger.error(f"[✗] Ingestion process failed after {duration:.2f}s")
                
        return total_success
        
    def _backup_existing_dbs(self) -> None:
        """Backup existing vector databases"""
        try:
            backup_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            vectordb_path = Path("vectordb")
            
            if vectordb_path.exists():
                backup_path = Path(f"vectordb_backup_{backup_time}")
                logger.info(f"Backing up existing databases to {backup_path}")
                
                # Copy entire vectordb directory
                import shutil
                shutil.copytree(vectordb_path, backup_path)
                
        except Exception as e:
            logger.warning(f"Database backup failed: {str(e)}")

async def main():
    """Main entry point"""
    try:
        # Initialize ingester with configuration
        config = IngestionConfig(
            parallel_ingestion=True,
            validate_output=True,
            backup_existing=True,
            compute_stats=True
        )
        
        ingester = KnowledgeIngester(config)
        
        # Run ingestion
        success = await ingester.ingest_all()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Ingestion failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
