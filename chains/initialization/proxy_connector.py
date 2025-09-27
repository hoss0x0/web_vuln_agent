import json
import os
import logging
import ssl
from typing import Dict, Optional, Union, List
from dataclasses import dataclass
from pathlib import Path
import yaml
import requests
import aiohttp
from urllib.parse import urlparse
import socket
import asyncio
from datetime import datetime, timedelta

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class ProxyConfig:
    """Configuration for proxy settings"""
    enabled: bool = False
    url: str = "http://127.0.0.1:8080"
    username: Optional[str] = None
    password: Optional[str] = None
    bypass_patterns: List[str] = None
    cert_path: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    protocols: List[str] = None
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ProxyConfig':
        """Load proxy configuration from YAML file"""
        if not os.path.exists(config_path):
            logger.warning(f"Config file not found: {config_path}")
            return cls()
            
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
                    
            return cls(
                enabled=config.get('use_proxy', False),
                url=config.get('proxy_url', "http://127.0.0.1:8080"),
                username=config.get('proxy_username'),
                password=config.get('proxy_password'),
                bypass_patterns=config.get('bypass_patterns', []),
                cert_path=config.get('proxy_cert_path'),
                timeout=config.get('proxy_timeout', 30),
                max_retries=config.get('proxy_max_retries', 3),
                verify_ssl=config.get('proxy_verify_ssl', True),
                protocols=config.get('proxy_protocols', ['http', 'https'])
            )
        except Exception as e:
            logger.error(f"Failed to load proxy config: {str(e)}")
            return cls()

class ProxyConnector:
    """Enhanced proxy connector with advanced features"""
    
    def __init__(self, config_path: str = "config/proxy_config.yaml"):
        self.config = ProxyConfig.from_file(config_path)
        self._ssl_context = self._setup_ssl_context()
        self._last_health_check = None
        self._health_check_interval = timedelta(minutes=5)
        self._connection_pool = {}
        
    def _setup_ssl_context(self) -> ssl.SSLContext:
        """Configure SSL context with custom certificates"""
        context = ssl.create_default_context()
        
        if self.config.cert_path:
            try:
                context.load_verify_locations(self.config.cert_path)
                logger.info(f"Loaded custom certificate from {self.config.cert_path}")
            except Exception as e:
                logger.error(f"Failed to load certificate: {str(e)}")
                
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification disabled - security risk!")
            
        return context
        
    def _should_bypass_proxy(self, url: str) -> bool:
        """Check if URL matches bypass patterns"""
        if not self.config.bypass_patterns:
            return False
            
        host = urlparse(url).netloc
        return any(
            pattern in host
            for pattern in self.config.bypass_patterns
        )
        
    async def _check_proxy_health(self) -> bool:
        """Check if proxy is responsive"""
        if not self.config.enabled:
            return False
            
        try:
            proxy_host = urlparse(self.config.url).netloc
            host, port = proxy_host.split(':')
            
            # Try TCP connection
            reader, writer = await asyncio.open_connection(host, int(port))
            writer.close()
            await writer.wait_closed()
            
            self._last_health_check = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"Proxy health check failed: {str(e)}")
            return False
            
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate proxy authentication headers"""
        headers = {}
        
        if self.config.username and self.config.password:
            import base64
            auth = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode()
            headers['Proxy-Authorization'] = f'Basic {auth}'
            
        return headers
        
    async def configure_session(
        self,
        session: Union[requests.Session, aiohttp.ClientSession]
    ) -> Union[requests.Session, aiohttp.ClientSession]:
        """Configure session with proxy settings"""
        if not self.config.enabled:
            logger.info("Proxy not enabled")
            return session
            
        # Check proxy health if needed
        if (
            not self._last_health_check or
            datetime.now() - self._last_health_check > self._health_check_interval
        ):
            if not await self._check_proxy_health():
                raise ConnectionError("Proxy is not available")
                
        try:
            if isinstance(session, requests.Session):
                return await self._configure_requests_session(session)
            elif isinstance(session, aiohttp.ClientSession):
                return await self._configure_aiohttp_session(session)
            else:
                raise ValueError(f"Unsupported session type: {type(session)}")
                
        except Exception as e:
            logger.error(f"Failed to configure proxy: {str(e)}")
            raise
            
    async def _configure_requests_session(
        self, session: requests.Session
    ) -> requests.Session:
        """Configure requests session with proxy"""
        proxy_settings = {}
        
        for protocol in self.config.protocols:
            proxy_settings[protocol] = self.config.url
            
        session.proxies.update(proxy_settings)
        session.verify = self.config.verify_ssl
        
        if self.config.cert_path:
            session.verify = self.config.cert_path
            
        session.headers.update(self._get_auth_headers())
        
        # Configure retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        logger.info(f"Configured requests session with proxy: {self.config.url}")
        return session
        
    async def _configure_aiohttp_session(
        self, session: aiohttp.ClientSession
    ) -> aiohttp.ClientSession:
        """Configure aiohttp session with proxy"""
        proxy_auth = None
        if self.config.username and self.config.password:
            proxy_auth = aiohttp.BasicAuth(
                self.config.username,
                self.config.password
            )
            
        # Create new session with proxy settings
        new_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                ssl=self._ssl_context,
                limit=100,
                ttl_dns_cache=300
            ),
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            headers=self._get_auth_headers()
        )
        
        # Copy original session attributes
        new_session._base_url = getattr(session, '_base_url', None)
        new_session._default_headers = {
            **getattr(session, '_default_headers', {}),
            **self._get_auth_headers()
        }
        
        logger.info(f"Configured aiohttp session with proxy: {self.config.url}")
        return new_session
        
    async def get_proxy_info(self) -> Dict:
        """Get current proxy configuration and status"""
        return {
            "enabled": self.config.enabled,
            "url": self.config.url,
            "protocols": self.config.protocols,
            "verify_ssl": self.config.verify_ssl,
            "bypass_patterns": self.config.bypass_patterns,
            "last_health_check": self._last_health_check,
            "is_healthy": await self._check_proxy_health() if self.config.enabled else None
        }

# Legacy support
def configure_proxy(session):
    """Legacy wrapper for backward compatibility"""
    connector = ProxyConnector()
    return asyncio.run(connector.configure_session(session))
