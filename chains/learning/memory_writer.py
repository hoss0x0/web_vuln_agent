import json
import logging
import os
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
from pathlib import Path
import aiofiles
import asyncio
from concurrent.futures import ThreadPoolExecutor
import gzip
import shutil
import yaml
from enum import Enum
import json
import jsonschema
from collections import deque

from utils.logger import setup_logger

logger = setup_logger(__name__)

class FindingType(Enum):
    """Types of security findings"""
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    WEAKNESS = "weakness"
    INSIGHT = "insight"

class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    """Structured security finding"""
    id: str
    type: FindingType
    title: str
    description: str
    severity: Severity
    evidence: Dict[str, Any]
    metadata: Dict[str, Any]
    timestamp: str
    hash: str
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Finding':
        """Create Finding from dictionary"""
        return cls(
            id=data.get('id', ''),
            type=FindingType(data.get('type', 'vulnerability')),
            title=data.get('title', ''),
            description=data.get('description', ''),
            severity=Severity(data.get('severity', 'medium')),
            evidence=data.get('evidence', {}),
            metadata=data.get('metadata', {}),
            timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
            hash=data.get('hash', '')
        )

class MemoryWriter:
    """Enhanced memory writer with advanced features"""
    
    def __init__(self):
        self._load_config()
        self._setup_storage()
        self._init_schema()
        self._recent_findings = deque(maxlen=100)
        self._executor = ThreadPoolExecutor(max_workers=4)
        
    def _load_config(self) -> None:
        """Load writer configuration"""
        try:
            config_path = Path("config/memory_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                
            self.memory_dir = Path(config.get('memory_dir', 'memory'))
            self.findings_file = self.memory_dir / config.get('findings_file', 'findings.jsonl')
            self.backup_dir = self.memory_dir / config.get('backup_dir', 'backups')
            self.compress_files = config.get('compress_files', True)
            self.max_file_size = config.get('max_file_size', 10 * 1024 * 1024)  # 10MB
            self.rotation_count = config.get('rotation_count', 5)
            self.validate_schema = config.get('validate_schema', True)
            self.deduplicate = config.get('deduplicate', True)
            
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            raise
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            'memory_dir': 'memory',
            'findings_file': 'findings.jsonl',
            'backup_dir': 'backups',
            'compress_files': True,
            'max_file_size': 10 * 1024 * 1024,
            'rotation_count': 5,
            'validate_schema': True,
            'deduplicate': True,
            'storage': {
                'compression_level': 9,
                'backup_interval': 86400,  # 24 hours
                'cleanup_interval': 604800  # 7 days
            },
            'validation': {
                'max_title_length': 200,
                'max_description_length': 2000,
                'required_fields': [
                    'type',
                    'title',
                    'description',
                    'severity'
                ]
            }
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _setup_storage(self) -> None:
        """Set up storage directories"""
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.findings_file.exists():
            self.findings_file.touch()
            
    def _init_schema(self) -> None:
        """Initialize JSON schema for validation"""
        self.schema = {
            "type": "object",
            "required": ["type", "title", "description", "severity"],
            "properties": {
                "id": {"type": "string"},
                "type": {"type": "string", "enum": [t.value for t in FindingType]},
                "title": {"type": "string", "maxLength": 200},
                "description": {"type": "string", "maxLength": 2000},
                "severity": {"type": "string", "enum": [s.value for s in Severity]},
                "evidence": {"type": "object"},
                "metadata": {"type": "object"},
                "timestamp": {"type": "string", "format": "date-time"},
                "hash": {"type": "string"}
            }
        }
        
    def _validate_finding(self, finding: Dict) -> None:
        """Validate finding against schema"""
        if self.validate_schema:
            try:
                jsonschema.validate(finding, self.schema)
            except jsonschema.exceptions.ValidationError as e:
                raise ValueError(f"Invalid finding format: {str(e)}")
                
    def _generate_finding_hash(self, finding: Dict) -> str:
        """Generate unique hash for finding"""
        hash_content = f"{finding.get('type')}:{finding.get('title')}:{finding.get('description')}"
        return hashlib.sha256(hash_content.encode()).hexdigest()
        
    def _should_rotate_file(self) -> bool:
        """Check if file should be rotated"""
        return self.findings_file.stat().st_size > self.max_file_size
        
    async def _rotate_files(self) -> None:
        """Rotate log files"""
        if not self._should_rotate_file():
            return
            
        for i in range(self.rotation_count - 1, -1, -1):
            src = self.findings_file if i == 0 else self.findings_file.with_suffix(f'.{i}')
            dst = self.findings_file.with_suffix(f'.{i + 1}')
            
            if src.exists():
                if self.compress_files and i == 0:
                    # Compress the current file
                    with open(src, 'rb') as f_in:
                        with gzip.open(str(dst) + '.gz', 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                else:
                    shutil.move(str(src), str(dst))
                    
        # Create new empty file
        self.findings_file.touch()
        
    async def _backup_findings(self) -> None:
        """Create backup of findings"""
        backup_file = self.backup_dir / f"findings_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl.gz"
        
        with open(self.findings_file, 'rb') as f_in:
            with gzip.open(str(backup_file), 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
                
    async def write_memory(self, finding: Union[Dict, Finding]) -> None:
        """Write finding to memory with validation and safety checks"""
        try:
            # Convert Finding object to dict if needed
            if isinstance(finding, Finding):
                finding_dict = asdict(finding)
            else:
                finding_dict = finding
                
            # Add metadata if missing
            if 'metadata' not in finding_dict:
                finding_dict['metadata'] = {}
                
            # Add timestamp if missing
            if 'timestamp' not in finding_dict:
                finding_dict['timestamp'] = datetime.utcnow().isoformat()
                
            # Generate hash if missing
            if 'hash' not in finding_dict:
                finding_dict['hash'] = self._generate_finding_hash(finding_dict)
                
            # Validate finding
            self._validate_finding(finding_dict)
            
            # Check for duplicates
            if self.deduplicate and finding_dict['hash'] in self._recent_findings:
                logger.info(f"Duplicate finding skipped: {finding_dict['title']}")
                return
                
            # Rotate files if needed
            await self._rotate_files()
            
            # Write finding
            async with aiofiles.open(self.findings_file, "a", encoding="utf-8") as f:
                await f.write(json.dumps(finding_dict) + "\n")
                
            # Update recent findings
            self._recent_findings.append(finding_dict['hash'])
            
            # Create backup if needed
            if self._should_backup():
                await self._backup_findings()
                
            logger.info(f"Finding written to memory: {finding_dict['title']}")
            
        except Exception as e:
            logger.error(f"Failed to write finding: {str(e)}")
            raise
            
    def _should_backup(self) -> bool:
        """Check if backup should be created"""
        try:
            last_backup = max(self.backup_dir.glob("findings_backup_*.jsonl.gz")).stat().st_mtime
            return (datetime.now().timestamp() - last_backup) > 86400  # 24 hours
        except ValueError:
            return True
            
    async def read_findings(
        self,
        limit: Optional[int] = None,
        filter_func: Optional[callable] = None
    ) -> List[Finding]:
        """Read findings from memory"""
        findings = []
        
        async with aiofiles.open(self.findings_file, "r", encoding="utf-8") as f:
            async for line in f:
                if line.strip():
                    finding_dict = json.loads(line)
                    if filter_func and not filter_func(finding_dict):
                        continue
                        
                    findings.append(Finding.from_dict(finding_dict))
                    
                    if limit and len(findings) >= limit:
                        break
                        
        return findings
        
    async def cleanup_old_backups(self) -> None:
        """Clean up old backup files"""
        try:
            backups = sorted(self.backup_dir.glob("findings_backup_*.jsonl.gz"))
            if len(backups) > self.rotation_count:
                for backup in backups[:-self.rotation_count]:
                    backup.unlink()
                    
        except Exception as e:
            logger.error(f"Failed to clean up backups: {str(e)}")
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get memory statistics"""
        return {
            "total_size": self.findings_file.stat().st_size,
            "backup_count": len(list(self.backup_dir.glob("findings_backup_*.jsonl.gz"))),
            "last_backup": max(self.backup_dir.glob("findings_backup_*.jsonl.gz")).stat().st_mtime,
            "findings_count": sum(1 for _ in open(self.findings_file)),
            "recent_findings": len(self._recent_findings)
        }

# Legacy support
def write_memory(finding: Dict) -> None:
    """Legacy wrapper for backward compatibility"""
    writer = MemoryWriter()
    asyncio.run(writer.write_memory(finding))
