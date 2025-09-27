import json
import logging
import asyncio
import ssl
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
import jwt
from urllib.parse import urlparse
import yaml

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class AuthConfig:
    """Configuration for authentication checks"""
    headers: Dict[str, str]
    tokens: Dict[str, str]
    cookies: Dict[str, str]
    certificate_paths: Dict[str, str]
    proxy_settings: Dict[str, str]
    timeout_seconds: int
    max_retries: int
    verify_ssl: bool
    allowed_schemes: Set[str]
    user_agent: str
    
    @classmethod
    def from_file(cls, config_path: str) -> 'AuthConfig':
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        return cls(
            headers=config.get('headers', {}),
            tokens=config.get('tokens', {}),
            cookies=config.get('cookies', {}),
            certificate_paths=config.get('certificates', {}),
            proxy_settings=config.get('proxies', {}),
            timeout_seconds=config.get('timeout', 30),
            max_retries=config.get('max_retries', 3),
            verify_ssl=config.get('verify_ssl', True),
            allowed_schemes=set(config.get('allowed_schemes', ['https'])),
            user_agent=config.get('user_agent', 'WebVulnAgent/1.0')
        )

@dataclass
class AuthCheckResult:
    """Result of authorization check for a target"""
    target: str
    timestamp: str
    status_code: Optional[int]
    reachable: bool
    response_time: float
    headers: Dict[str, str]
    auth_methods: List[str]
    security_headers: Dict[str, bool]
    certificate_info: Optional[Dict[str, Any]]
    error: Optional[str] = None

class AuthorizationChecker:
    """Enhanced authorization checker with security validations"""
    
    def __init__(self, config_path: str = "config/auth_config.yaml"):
        self.config = AuthConfig.from_file(config_path)
        self._setup_ssl_context()
        self.results_cache: Dict[str, AuthCheckResult] = {}
        self.required_security_headers = {
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-XSS-Protection'
        }
        
    def _setup_ssl_context(self) -> None:
        """Configure SSL context with custom certificates"""
        self.ssl_context = ssl.create_default_context()
        
        for domain, cert_path in self.config.certificate_paths.items():
            try:
                self.ssl_context.load_verify_locations(cert_path)
            except Exception as e:
                logger.error(f"Failed to load certificate for {domain}: {str(e)}")
                
    def _validate_url(self, url: str) -> bool:
        """Validate URL scheme and format"""
        try:
            parsed = urlparse(url)
            return bool(
                parsed.scheme in self.config.allowed_schemes and
                parsed.netloc and
                len(url) < 2048  # Standard URL length limit
            )
        except Exception:
            return False
            
    async def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, bool]:
        """Check for required security headers"""
        return {
            header: header.lower() in {h.lower() for h in headers}
            for header in self.required_security_headers
        }
        
    async def _get_certificate_info(self, url: str) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return None
                
            cert = await asyncio.to_thread(
                ssl.get_server_certificate,
                (parsed.hostname, 443)
            )
            x509 = ssl.PEM_cert_to_DER_cert(cert)
            
            return {
                'issuer': x509.get_issuer().commonName,
                'subject': x509.get_subject().commonName,
                'version': x509.get_version(),
                'expired': x509.has_expired(),
                'valid_from': x509.get_notBefore(),
                'valid_until': x509.get_notAfter()
            }
        except Exception as e:
            logger.warning(f"Failed to get certificate info for {url}: {str(e)}")
            return None
            
    async def _verify_jwt(self, token: str) -> bool:
        """Verify JWT token if present"""
        try:
            jwt.decode(token, options={"verify_signature": False})
            return True
        except jwt.InvalidTokenError:
            return False
            
    def _prepare_request_headers(self, url: str) -> Dict[str, str]:
        """Prepare headers with auth tokens"""
        headers = self.config.headers.copy()
        headers['User-Agent'] = self.config.user_agent
        
        # Add domain-specific tokens
        domain = urlparse(url).netloc
        if token := self.config.tokens.get(domain):
            if self._verify_jwt(token):
                headers['Authorization'] = f'Bearer {token}'
                
        return headers
        
    async def check_single_target(self, url: str) -> AuthCheckResult:
        """Check authorization for a single target"""
        if not self._validate_url(url):
            return AuthCheckResult(
                target=url,
                timestamp=datetime.utcnow().isoformat(),
                status_code=None,
                reachable=False,
                response_time=0,
                headers={},
                auth_methods=[],
                security_headers={},
                certificate_info=None,
                error="Invalid URL"
            )
            
        timeout = ClientTimeout(total=self.config.timeout_seconds)
        conn = TCPConnector(ssl=self.ssl_context if self.config.verify_ssl else False)
        
        async with aiohttp.ClientSession(
            connector=conn,
            timeout=timeout,
            headers=self._prepare_request_headers(url),
            cookies=self.config.cookies
        ) as session:
            start_time = datetime.now()
            
            try:
                for attempt in range(self.config.max_retries):
                    try:
                        async with session.get(
                            url,
                            proxy=self.config.proxy_settings.get(urlparse(url).scheme)
                        ) as response:
                            headers = dict(response.headers)
                            auth_methods = self._detect_auth_methods(headers)
                            security_headers = await self._check_security_headers(headers)
                            cert_info = await self._get_certificate_info(url)
                            
                            result = AuthCheckResult(
                                target=url,
                                timestamp=datetime.utcnow().isoformat(),
                                status_code=response.status,
                                reachable=response.status < 500,
                                response_time=(datetime.now() - start_time).total_seconds(),
                                headers=headers,
                                auth_methods=auth_methods,
                                security_headers=security_headers,
                                certificate_info=cert_info
                            )
                            
                            # Cache successful results
                            self.results_cache[url] = result
                            return result
                            
                    except aiohttp.ClientError as e:
                        if attempt == self.config.max_retries - 1:
                            raise
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        
            except Exception as e:
                logger.error(f"Failed to check {url}: {str(e)}")
                return AuthCheckResult(
                    target=url,
                    timestamp=datetime.utcnow().isoformat(),
                    status_code=None,
                    reachable=False,
                    response_time=(datetime.now() - start_time).total_seconds(),
                    headers={},
                    auth_methods=[],
                    security_headers={},
                    certificate_info=None,
                    error=str(e)
                )
                
    def _detect_auth_methods(self, headers: Dict[str, str]) -> List[str]:
        """Detect authentication methods from headers"""
        auth_methods = []
        
        www_auth = headers.get('WWW-Authenticate', '').lower()
        if 'basic' in www_auth:
            auth_methods.append('basic')
        if 'bearer' in www_auth:
            auth_methods.append('bearer')
        if 'digest' in www_auth:
            auth_methods.append('digest')
        if 'ntlm' in www_auth:
            auth_methods.append('ntlm')
        
        if 'set-cookie' in headers:
            auth_methods.append('cookie')
            
        return auth_methods
        
    async def check_auth(self) -> List[AuthCheckResult]:
        """Check authorization for all targets in scope"""
        try:
            # Load and validate engagement scope
            engagement_path = Path("config/engagement.json")
            if not engagement_path.exists():
                raise FileNotFoundError("Engagement config not found")
                
            with open(engagement_path, "r") as f:
                scope = json.load(f).get("scope", [])
                
            if not scope:
                logger.warning("Empty scope in engagement config")
                return []
                
            # Filter out invalid URLs
            valid_urls = [url for url in scope if self._validate_url(url)]
            if len(valid_urls) < len(scope):
                logger.warning(f"Filtered out {len(scope) - len(valid_urls)} invalid URLs")
                
            # Check all targets concurrently
            tasks = [self.check_single_target(url) for url in valid_urls]
            results = await asyncio.gather(*tasks)
            
            # Log summary
            success_count = sum(1 for r in results if r.reachable)
            logger.info(f"Authorization check completed: {success_count}/{len(results)} targets reachable")
            
            return results
            
        except Exception as e:
            logger.error(f"Authorization check failed: {str(e)}")
            raise
