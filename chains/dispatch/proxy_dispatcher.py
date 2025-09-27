import os
import json
import time
import logging
import asyncio
import aiohttp
import requests
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, Timeout, ConnectionError
from urllib.parse import urlparse

from utils.logger import setup_logger
from chains.safety.stop_trigger import StopTrigger

logger = setup_logger(__name__)

class ProxyType(Enum):
    """Supported proxy types"""
    BURP = "burp"
    ZAPI = "zap"
    CUSTOM = "custom"
    DIRECT = "direct"

@dataclass
class ProxyConfig:
    """Proxy configuration settings"""
    type: ProxyType
    host: str = "127.0.0.1"
    port: int = 8080
    api_key: Optional[str] = None
    verify_ssl: bool = False
    timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 1
    scope_constraints: Optional[List[str]] = None
    excluded_paths: Optional[List[str]] = None

class ProxyDispatcher:
    """Enhanced proxy dispatcher with advanced features and multiple proxy support"""

    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig(type=ProxyType.BURP)
        self.session = self._create_session()
        self.stop_trigger = StopTrigger()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate proxy configuration"""
        if not isinstance(self.config.port, int) or not 1 <= self.config.port <= 65535:
            raise ValueError("Invalid port number")
            
        if self.config.api_key and len(self.config.api_key) < 32:
            logger.warning("API key seems too short, might not be secure")
            
        try:
            # Test proxy connection
            self._test_proxy_connection()
        except Exception as e:
            logger.error(f"Proxy connection test failed: {str(e)}")
            raise

    def _create_session(self) -> requests.Session:
        """Create and configure requests session"""
        session = requests.Session()
        session.verify = self.config.verify_ssl
        
        # Configure proxy
        if self.config.type != ProxyType.DIRECT:
            session.proxies = {
                'http': f'http://{self.config.host}:{self.config.port}',
                'https': f'http://{self.config.host}:{self.config.port}'
            }
            
        # Configure retry strategy
        retry = requests.adapters.Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[500, 502, 503, 504]
        )
        
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        return session

    def _test_proxy_connection(self) -> None:
        """Test proxy connection and features"""
        try:
            if self.config.type == ProxyType.BURP:
                r = self.session.get(
                    f'http://{self.config.host}:{self.config.port}/burp/versions',
                    timeout=5
                )
                if r.status_code != 200:
                    raise ConnectionError("Burp proxy not responding correctly")
                    
            elif self.config.type == ProxyType.ZAPI:
                r = self.session.get(
                    f'http://{self.config.host}:{self.config.port}/JSON/core/view/version/',
                    headers={'X-ZAP-API-Key': self.config.api_key},
                    timeout=5
                )
                if r.status_code != 200:
                    raise ConnectionError("ZAP proxy not responding correctly")
                    
        except Exception as e:
            logger.error(f"Proxy connection test failed: {str(e)}")
            raise

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within defined scope"""
        if not self.config.scope_constraints:
            return True
            
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Check against scope patterns
        for pattern in self.config.scope_constraints:
            if pattern.startswith("*"):
                if target.endswith(pattern[1:]):
                    return True
            elif pattern.endswith("*"):
                if target.startswith(pattern[:-1]):
                    return True
            else:
                if target == pattern:
                    return True
                    
        return False

    def _is_excluded(self, url: str) -> bool:
        """Check if URL is in exclusion list"""
        if not self.config.excluded_paths:
            return False
            
        parsed = urlparse(url)
        path = parsed.path
        
        return any(
            excluded in path
            for excluded in self.config.excluded_paths
        )

    async def dispatch_async(self, request_data: Dict) -> Dict:
        """
        Asynchronously dispatch request through proxy
        
        Args:
            request_data: Request data to dispatch
            
        Returns:
            Dict containing proxy response or error details
        """
        try:
            # Validate request data
            if not isinstance(request_data, dict):
                raise ValueError("Request data must be a dictionary")
                
            url = request_data.get('url')
            if not url:
                raise ValueError("URL is required in request data")
                
            # Check scope and exclusions
            if not self._is_in_scope(url):
                return {"error": "URL not in scope", "url": url}
                
            if self._is_excluded(url):
                return {"error": "URL in exclusion list", "url": url}
                
            # Prepare request
            headers = self._prepare_headers(request_data)
            
            async with aiohttp.ClientSession() as session:
                proxy_url = f"http://{self.config.host}:{self.config.port}/dispatch"
                
                async with session.post(
                    proxy_url,
                    json=request_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    
                    if response.status == 429:  # Rate limited
                        await asyncio.sleep(self.config.retry_delay)
                        return await self.dispatch_async(request_data)
                        
                    response_data = await response.json()
                    
                    # Log response metadata
                    logger.debug(f"Proxy response status: {response.status}")
                    if response.status != 200:
                        logger.warning(f"Proxy returned non-200 status: {response.status}")
                        
                    return response_data

        except aiohttp.ClientError as e:
            logger.error(f"Proxy connection error: {str(e)}")
            return {"error": "Proxy connection failed", "details": str(e)}
            
        except asyncio.TimeoutError:
            logger.error("Proxy request timed out")
            return {"error": "Request timeout"}
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON response from proxy")
            return {"error": "Invalid proxy response"}
            
        except Exception as e:
            logger.error(f"Unexpected error in proxy dispatch: {str(e)}")
            return {"error": "Unexpected error", "details": str(e)}

    def _prepare_headers(self, request_data: Dict) -> Dict:
        """Prepare headers for proxy request"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'WebVulnAgent/1.0'
        }
        
        if self.config.api_key:
            if self.config.type == ProxyType.BURP:
                headers['Authorization'] = f'Bearer {self.config.api_key}'
            elif self.config.type == ProxyType.ZAPI:
                headers['X-ZAP-API-Key'] = self.config.api_key
                
        return headers

    def dispatch_to_proxy(self, request_data: Dict) -> Dict:
        """
        Synchronous dispatch request through proxy (legacy support)
        
        Args:
            request_data: Request data to dispatch
            
        Returns:
            Dict containing proxy response or error details
        """
        try:
            # Validate request
            if not isinstance(request_data, dict):
                raise ValueError("Request data must be a dictionary")
                
            url = request_data.get('url')
            if not url:
                raise ValueError("URL is required in request data")
                
            # Check scope and exclusions
            if not self._is_in_scope(url):
                return {"error": "URL not in scope", "url": url}
                
            if self._is_excluded(url):
                return {"error": "URL in exclusion list", "url": url}
                
            # Prepare request
            headers = self._prepare_headers(request_data)
            proxy_url = f"http://{self.config.host}:{self.config.port}/dispatch"
            
            # Send request with retries
            for attempt in range(self.config.max_retries):
                try:
                    response = self.session.post(
                        proxy_url,
                        json=request_data,
                        headers=headers,
                        timeout=self.config.timeout
                    )
                    
                    if response.status_code == 429:  # Rate limited
                        time.sleep(self.config.retry_delay)
                        continue
                        
                    return response.json()
                    
                except (ConnectionError, Timeout) as e:
                    if attempt == self.config.max_retries - 1:
                        raise
                    time.sleep(self.config.retry_delay)
                    
        except RequestException as e:
            logger.error(f"Proxy request failed: {str(e)}")
            return {"error": "Proxy request failed", "details": str(e)}
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON response from proxy")
            return {"error": "Invalid proxy response"}
            
        except Exception as e:
            logger.error(f"Unexpected error in proxy dispatch: {str(e)}")
            return {"error": "Unexpected error", "details": str(e)}

    async def close(self):
        """Cleanup resources"""
        self.session.close()
        self.executor.shutdown(wait=True)

# Legacy support function
def dispatch_to_proxy(request_data: Dict) -> Dict:
    """Legacy wrapper for backward compatibility"""
    dispatcher = ProxyDispatcher()
    return dispatcher.dispatch_to_proxy(request_data)
