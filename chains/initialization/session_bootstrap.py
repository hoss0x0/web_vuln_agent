import json
import os
import logging
import ssl
import time
from typing import Dict, Optional, Union, List, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import yaml
import jwt
import requests
import aiohttp
from urllib.parse import urlparse
import hashlib
import uuid
from cryptography.fernet import Fernet
import asyncio
from concurrent.futures import ThreadPoolExecutor

from utils.logger import setup_logger
from chains.safety.safety_monitor import SafetyMonitor
from chains.waf.waf_detector import WafDetector

logger = setup_logger(__name__)

@dataclass
class SessionConfig:
    """Configuration for session management"""
    user_agent: str
    tokens: Dict[str, str]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    timeout: int
    max_retries: int
    verify_ssl: bool
    ssl_cert_path: Optional[str]
    ssl_key_path: Optional[str]
    encryption_key: Optional[str]
    connection_pool_size: int
    keepalive_timeout: int
    compression: bool
    retry_statuses: List[int]
    allowed_protocols: List[str]
    session_ttl: int
    
    @classmethod
    def from_file(cls, config_path: str) -> 'SessionConfig':
        """Load session configuration from YAML/JSON file"""
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
                    
            return cls(
                user_agent=config.get('user_agent', 'WebVulnAgent/2.0'),
                tokens=config.get('tokens', {}),
                headers=config.get('headers', {}),
                cookies=config.get('cookies', {}),
                timeout=config.get('timeout', 30),
                max_retries=config.get('max_retries', 3),
                verify_ssl=config.get('verify_ssl', True),
                ssl_cert_path=config.get('ssl_cert_path'),
                ssl_key_path=config.get('ssl_key_path'),
                encryption_key=config.get('encryption_key'),
                connection_pool_size=config.get('connection_pool_size', 100),
                keepalive_timeout=config.get('keepalive_timeout', 30),
                compression=config.get('compression', True),
                retry_statuses=config.get('retry_statuses', [408, 429, 500, 502, 503, 504]),
                allowed_protocols=config.get('allowed_protocols', ['http', 'https']),
                session_ttl=config.get('session_ttl', 3600)
            )
        except Exception as e:
            logger.error(f"Failed to load session config: {str(e)}")
            raise

class SessionManager:
    """Enhanced session management with security features"""
    
    def __init__(self, config_path: str = "config/session_config.yaml"):
        self.config = SessionConfig.from_file(config_path)
        self._ssl_context = self._setup_ssl_context()
        self.safety_monitor = SafetyMonitor()
        self.waf_detector = WafDetector()
        self._session_cache: Dict[str, Any] = {}
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._setup_encryption()
        
    def _setup_ssl_context(self) -> ssl.SSLContext:
        """Configure SSL context with custom certificates"""
        context = ssl.create_default_context()
        
        if self.config.ssl_cert_path and self.config.ssl_key_path:
            try:
                context.load_cert_chain(
                    self.config.ssl_cert_path,
                    self.config.ssl_key_path
                )
            except Exception as e:
                logger.error(f"Failed to load SSL certificates: {str(e)}")
                
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification disabled!")
            
        return context
        
    def _setup_encryption(self) -> None:
        """Initialize encryption for sensitive data"""
        if self.config.encryption_key:
            try:
                self.fernet = Fernet(self.config.encryption_key.encode())
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {str(e)}")
                self.fernet = None
        else:
            self.fernet = None
            
    def _encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data if encryption is enabled"""
        if self.fernet:
            return self.fernet.encrypt(data.encode()).decode()
        return data
        
    def _decrypt_sensitive_data(self, data: str) -> str:
        """Decrypt sensitive data if encryption is enabled"""
        if self.fernet:
            return self.fernet.decrypt(data.encode()).decode()
        return data
        
    async def _verify_token(self, token: str) -> bool:
        """Verify JWT token validity"""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get('exp')
            if exp and datetime.fromtimestamp(exp) <= datetime.now():
                return False
            return True
        except jwt.InvalidTokenError:
            return False
            
    def _get_session_headers(self) -> Dict[str, str]:
        """Prepare session headers with security considerations"""
        headers = {
            "User-Agent": self.config.user_agent,
            "X-Request-ID": str(uuid.uuid4()),
            "X-Session-ID": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        }
        
        # Add custom headers
        headers.update(self.config.headers)
        
        # Add security headers
        headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block"
        })
        
        return headers
        
    async def _setup_session_auth(
        self,
        session: Union[requests.Session, aiohttp.ClientSession]
    ) -> None:
        """Configure session authentication"""
        if "auth_token" in self.config.tokens:
            token = self.config.tokens["auth_token"]
            if await self._verify_token(token):
                if isinstance(session, requests.Session):
                    session.headers["Authorization"] = f"Bearer {token}"
                else:
                    session._default_headers["Authorization"] = f"Bearer {token}"
            else:
                logger.warning("Auth token is invalid or expired")
                
    async def bootstrap_session(
        self,
        session_type: str = "requests"
    ) -> Union[requests.Session, aiohttp.ClientSession]:
        """Create and configure a new session with enhanced security"""
        try:
            if session_type == "requests":
                return await self._bootstrap_requests_session()
            elif session_type == "aiohttp":
                return await self._bootstrap_aiohttp_session()
            else:
                raise ValueError(f"Unsupported session type: {session_type}")
                
        except Exception as e:
            logger.error(f"Session bootstrap failed: {str(e)}")
            raise
            
    async def _bootstrap_requests_session(self) -> requests.Session:
        """Bootstrap a requests session"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = requests.adapters.Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=self.config.retry_statuses
        )
        
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.connection_pool_size,
            pool_maxsize=self.config.connection_pool_size
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure SSL
        session.verify = self.config.verify_ssl
        if self.config.ssl_cert_path:
            session.cert = (
                self.config.ssl_cert_path,
                self.config.ssl_key_path
            )
            
        # Configure headers and auth
        session.headers.update(self._get_session_headers())
        await self._setup_session_auth(session)
        
        # Configure cookies
        for name, value in self.config.cookies.items():
            session.cookies.set(name, value)
            
        # Configure timeouts
        session.timeout = self.config.timeout
        
        return session
        
    async def _bootstrap_aiohttp_session(self) -> aiohttp.ClientSession:
        """Bootstrap an aiohttp session"""
        # Configure connection timeout
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=self.config.timeout/3,
            sock_read=self.config.timeout
        )
        
        # Configure connector
        connector = aiohttp.TCPConnector(
            ssl=self._ssl_context,
            limit=self.config.connection_pool_size,
            ttl_dns_cache=300,
            keepalive_timeout=self.config.keepalive_timeout
        )
        
        # Create session
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._get_session_headers(),
            cookies=self.config.cookies,
            compress=self.config.compression
        )
        
        await self._setup_session_auth(session)
        return session
        
    async def get_session_info(self) -> Dict:
        """Get current session configuration and status"""
        return {
            "user_agent": self.config.user_agent,
            "ssl_verified": self.config.verify_ssl,
            "encryption_enabled": bool(self.fernet),
            "compression_enabled": self.config.compression,
            "connection_pool_size": self.config.connection_pool_size,
            "keepalive_timeout": self.config.keepalive_timeout,
            "retry_config": {
                "max_retries": self.config.max_retries,
                "retry_statuses": self.config.retry_statuses
            },
            "protocols": self.config.allowed_protocols,
            "session_ttl": self.config.session_ttl
        }

# Legacy support
def bootstrap_session():
    """Legacy wrapper for backward compatibility"""
    manager = SessionManager()
    return asyncio.run(manager.bootstrap_session("requests"))
