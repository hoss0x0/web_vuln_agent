import json
import os
import logging
import hashlib
import gzip
import base64
import asyncio
from typing import Dict, Optional, Union, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from chains.learning.pii_masker import PIIMasker
from utils.logger import setup_logger

logger = setup_logger(__name__)

class LogLevel(Enum):
    """Log level for requests"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogFormat(Enum):
    """Supported log formats"""
    JSON = "json"
    JSONL = "jsonl"
    COMPRESSED = "gz"
    ENCRYPTED = "enc"

@dataclass
class RequestLogEntry:
    """Structure for request log entries"""
    timestamp: str
    request_id: str
    method: str
    url: str
    headers: Dict
    body: Optional[str]
    parameters: Dict
    cookies: Dict
    client_ip: Optional[str]
    user_agent: Optional[str]

@dataclass
class ResponseLogEntry:
    """Structure for response log entries"""
    timestamp: str
    request_id: str
    status_code: int
    headers: Dict
    body: Optional[str]
    response_time: float
    content_type: Optional[str]
    content_length: Optional[int]
    compression: Optional[str]

@dataclass
class LogConfig:
    """Configuration for request logging"""
    log_dir: str = "logs"
    format: LogFormat = LogFormat.JSONL
    max_size_mb: int = 100
    backup_count: int = 5
    compress_logs: bool = True
    encrypt_logs: bool = False
    encryption_key: Optional[str] = None
    mask_pii: bool = True
    max_body_size: int = 10000
    async_logging: bool = True
    include_headers: List[str] = None
    exclude_headers: List[str] = None
    log_level: LogLevel = LogLevel.INFO

class RequestLogger:
    """Enhanced request logger with advanced features"""

    def __init__(self, config: Optional[LogConfig] = None):
        self.config = config or LogConfig()
        self.pii_masker = PIIMasker()
        self.executor = ThreadPoolExecutor(max_workers=2)
        self._setup_logging()
        
        if self.config.encrypt_logs:
            self._setup_encryption()

    def _setup_logging(self) -> None:
        """Configure logging infrastructure"""
        try:
            # Create log directory
            os.makedirs(self.config.log_dir, exist_ok=True)
            
            # Setup log rotation
            log_file = os.path.join(self.config.log_dir, "requests.jsonl")
            handler = RotatingFileHandler(
                log_file,
                maxBytes=self.config.max_size_mb * 1024 * 1024,
                backupCount=self.config.backup_count
            )
            
            # Configure formatter
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            
            # Add handler to logger
            logger.addHandler(handler)
            
        except Exception as e:
            logger.error(f"Failed to setup logging: {str(e)}")
            raise

    def _setup_encryption(self) -> None:
        """Setup encryption for sensitive logs"""
        try:
            if not self.config.encryption_key:
                # Generate encryption key
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(b"default_key"))
                self.config.encryption_key = key
                
            self.fernet = Fernet(self.config.encryption_key)
            
            # Store salt securely
            salt_file = os.path.join(self.config.log_dir, ".salt")
            with open(salt_file, "wb") as f:
                f.write(salt)
                
        except Exception as e:
            logger.error(f"Failed to setup encryption: {str(e)}")
            raise

    def _generate_request_id(self, request: Dict) -> str:
        """Generate unique request ID"""
        components = [
            request.get("method", ""),
            request.get("url", ""),
            str(datetime.now().timestamp())
        ]
        return hashlib.sha256(
            "|".join(components).encode()
        ).hexdigest()[:12]

    def _mask_sensitive_data(self, data: Dict) -> Dict:
        """Mask sensitive data in logs"""
        if not self.config.mask_pii:
            return data
            
        return self.pii_masker.mask_data(data)

    def _filter_headers(self, headers: Dict) -> Dict:
        """Filter headers based on configuration"""
        if not headers:
            return {}
            
        if self.config.include_headers:
            return {
                k: v for k, v in headers.items()
                if k.lower() in [h.lower() for h in self.config.include_headers]
            }
            
        if self.config.exclude_headers:
            return {
                k: v for k, v in headers.items()
                if k.lower() not in [h.lower() for h in self.config.exclude_headers]
            }
            
        return headers

    def _truncate_body(self, body: Optional[str]) -> Optional[str]:
        """Truncate response body if too large"""
        if not body:
            return None
            
        if len(body) > self.config.max_body_size:
            return body[:self.config.max_body_size] + "... [truncated]"
            
        return body

    def _compress_log(self, log_entry: Dict) -> bytes:
        """Compress log entry"""
        return gzip.compress(json.dumps(log_entry).encode())

    def _encrypt_log(self, log_data: Union[str, bytes]) -> str:
        """Encrypt log data"""
        if isinstance(log_data, str):
            log_data = log_data.encode()
        return self.fernet.encrypt(log_data).decode()

    def _write_log(self, log_entry: Dict) -> None:
        """Write log entry to file"""
        try:
            log_path = os.path.join(
                self.config.log_dir,
                f"requests.{self.config.format.value}"
            )
            
            # Prepare log data
            log_data = json.dumps(log_entry)
            
            if self.config.compress_logs:
                log_data = self._compress_log(log_entry)
                
            if self.config.encrypt_logs:
                log_data = self._encrypt_log(log_data)
            
            # Write to file
            write_mode = "ab" if isinstance(log_data, bytes) else "a"
            with open(log_path, write_mode) as f:
                if isinstance(log_data, str):
                    f.write(log_data + "\n")
                else:
                    f.write(log_data)
                    
        except Exception as e:
            logger.error(f"Failed to write log: {str(e)}")

    async def log_request(
        self,
        request: Dict,
        response: Dict,
        level: Optional[LogLevel] = None
    ) -> None:
        """
        Log HTTP request and response with enhanced features
        
        Args:
            request: Request dictionary
            response: Response dictionary
            level: Log level for this entry
        """
        try:
            # Generate request ID
            request_id = self._generate_request_id(request)
            
            # Create request log entry
            request_entry = RequestLogEntry(
                timestamp=datetime.now().isoformat(),
                request_id=request_id,
                method=request.get("method", "UNKNOWN"),
                url=request.get("url", ""),
                headers=self._filter_headers(request.get("headers", {})),
                body=self._truncate_body(request.get("body")),
                parameters=request.get("parameters", {}),
                cookies=request.get("cookies", {}),
                client_ip=request.get("client_ip"),
                user_agent=request.get("user_agent")
            )
            
            # Create response log entry
            response_entry = ResponseLogEntry(
                timestamp=datetime.now().isoformat(),
                request_id=request_id,
                status_code=response.get("status_code", 0),
                headers=self._filter_headers(response.get("headers", {})),
                body=self._truncate_body(response.get("body")),
                response_time=response.get("response_time", 0.0),
                content_type=response.get("content_type"),
                content_length=response.get("content_length"),
                compression=response.get("compression")
            )
            
            # Combine entries
            log_entry = {
                "request": asdict(request_entry),
                "response": asdict(response_entry),
                "level": (level or self.config.log_level).value
            }
            
            # Mask sensitive data
            log_entry = self._mask_sensitive_data(log_entry)
            
            # Write log asynchronously
            if self.config.async_logging:
                self.executor.submit(self._write_log, log_entry)
            else:
                self._write_log(log_entry)
                
        except Exception as e:
            logger.error(f"Failed to log request: {str(e)}")

    async def get_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        level: Optional[LogLevel] = None,
        limit: Optional[int] = None
    ) -> List[Dict]:
        """Retrieve logs with filtering"""
        logs = []
        try:
            log_path = os.path.join(
                self.config.log_dir,
                f"requests.{self.config.format.value}"
            )
            
            if not os.path.exists(log_path):
                return logs
                
            read_mode = "rb" if self.config.compress_logs else "r"
            with open(log_path, read_mode) as f:
                for line in f:
                    try:
                        # Decompress if needed
                        if self.config.compress_logs:
                            line = gzip.decompress(line).decode()
                            
                        # Decrypt if needed
                        if self.config.encrypt_logs:
                            line = self.fernet.decrypt(line.encode()).decode()
                            
                        log_entry = json.loads(line)
                        
                        # Apply filters
                        if self._filter_log_entry(
                            log_entry, start_time, end_time, level
                        ):
                            logs.append(log_entry)
                            
                        if limit and len(logs) >= limit:
                            break
                            
                    except Exception as e:
                        logger.error(f"Failed to parse log entry: {str(e)}")
                        continue
                        
            return logs
            
        except Exception as e:
            logger.error(f"Failed to retrieve logs: {str(e)}")
            return logs

    def _filter_log_entry(
        self,
        entry: Dict,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        level: Optional[LogLevel]
    ) -> bool:
        """Filter log entry based on criteria"""
        try:
            # Check level
            if level and entry.get("level") != level.value:
                return False
                
            # Check time range
            entry_time = datetime.fromisoformat(
                entry["request"]["timestamp"].replace("Z", "+00:00")
            )
            
            if start_time and entry_time < start_time:
                return False
                
            if end_time and entry_time > end_time:
                return False
                
            return True
            
        except Exception:
            return False

    async def cleanup_old_logs(self, days: int = 30) -> None:
        """Clean up old log files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            log_dir = Path(self.config.log_dir)
            
            for log_file in log_dir.glob("requests.*"):
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    log_file.unlink()
                    logger.info(f"Deleted old log file: {log_file}")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup logs: {str(e)}")

    async def close(self) -> None:
        """Cleanup resources"""
        self.executor.shutdown(wait=True)

def log_request(request: Dict, response: Dict) -> None:
    """Legacy wrapper for backward compatibility"""
    logger = RequestLogger()
    asyncio.run(logger.log_request(request, response))
