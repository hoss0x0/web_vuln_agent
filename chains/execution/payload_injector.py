import logging
import json
import time
import hashlib
from typing import Dict, Union, Optional, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import re
from urllib.parse import urlencode, urlparse, parse_qs, quote, unquote
import requests
from requests.exceptions import RequestException, Timeout, TooManyRedirects
import aiohttp
import asyncio
from bs4 import BeautifulSoup

from utils.logger import setup_logger
from chains.safety.safety_monitor import SafetyMonitor
from chains.waf.waf_detector import WafDetector

logger = setup_logger(__name__)

class InjectionLocation(Enum):
    """Supported injection locations"""
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    MULTIPART = "multipart"
    JSON = "json"
    XML = "xml"

class ContentType(Enum):
    """Supported content types"""
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    TEXT = "text/plain"
    HTML = "text/html"

@dataclass
class InjectionContext:
    """Context for payload injection"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[Dict[str, Any]] = None
    query_params: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    timeout: int = 30
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    retry_count: int = 3
    retry_delay: int = 1

class PayloadInjector:
    """Enhanced payload injection with security features"""

    def __init__(self):
        self.safety_monitor = SafetyMonitor()
        self.waf_detector = WafDetector()
        self.supported_methods = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
        self.max_payload_size = 8192  # 8KB limit
        self.request_history: List[Dict] = []
        
    async def inject_payload(
        self,
        session: Union[requests.Session, aiohttp.ClientSession],
        context: InjectionContext,
        param_name: str,
        mutated_payload: str,
        location: Union[str, InjectionLocation],
        content_type: Optional[Union[str, ContentType]] = None
    ) -> Union[requests.Response, aiohttp.ClientResponse]:
        """
        Inject payload with advanced security features and error handling
        
        Args:
            session: HTTP session (requests or aiohttp)
            context: Injection context with request details
            param_name: Parameter name to inject
            mutated_payload: Payload to inject
            location: Injection location (query, body, header, etc)
            content_type: Content type for the request
            
        Returns:
            HTTP response object
        
        Raises:
            ValueError: For invalid inputs
            RequestException: For request failures
        """
        try:
            # Input validation
            self._validate_inputs(context, param_name, mutated_payload, location)
            
            # Convert string location to enum if needed
            if isinstance(location, str):
                location = InjectionLocation(location.lower())
                
            # Convert string content type to enum if needed
            if isinstance(content_type, str):
                content_type = ContentType(content_type.lower())
                
            # Check safety constraints
            if not self.safety_monitor.is_safe_payload(mutated_payload):
                raise ValueError("Payload failed safety checks")
                
            # Check size limits
            if len(mutated_payload.encode()) > self.max_payload_size:
                raise ValueError(f"Payload exceeds size limit of {self.max_payload_size} bytes")
                
            # Prepare request data
            request_data = await self._prepare_request_data(
                context, param_name, mutated_payload, location, content_type
            )
            
            # Add request to history
            self._add_to_history(request_data)
            
            # Send request with retries
            response = await self._send_request_with_retry(
                session, request_data, context
            )
            
            # Check for WAF detection
            if self.waf_detector.is_waf_response(response):
                logger.warning("WAF detected in response")
                request_data['waf_detected'] = True
                
            return response
            
        except Exception as e:
            logger.error(f"Payload injection failed: {str(e)}")
            raise

    def _validate_inputs(
        self,
        context: InjectionContext,
        param_name: str,
        payload: str,
        location: Union[str, InjectionLocation]
    ) -> None:
        """Validate input parameters"""
        if not context.url or not urlparse(context.url).scheme:
            raise ValueError("Invalid URL")
            
        if not context.method or context.method.upper() not in self.supported_methods:
            raise ValueError(f"Unsupported method: {context.method}")
            
        if not param_name or not isinstance(param_name, str):
            raise ValueError("Invalid parameter name")
            
        if not payload or not isinstance(payload, str):
            raise ValueError("Invalid payload")
            
        if isinstance(location, str) and location.lower() not in {loc.value for loc in InjectionLocation}:
            raise ValueError(f"Unsupported location: {location}")

    async def _prepare_request_data(
        self,
        context: InjectionContext,
        param_name: str,
        payload: str,
        location: InjectionLocation,
        content_type: Optional[ContentType]
    ) -> Dict[str, Any]:
        """Prepare request data based on injection location"""
        request_data = {
            'url': context.url,
            'method': context.method.upper(),
            'headers': context.headers.copy(),
            'verify': context.verify_ssl,
            'allow_redirects': context.follow_redirects,
            'max_redirects': context.max_redirects,
            'timeout': context.timeout
        }

        # Handle different injection locations
        if location == InjectionLocation.QUERY:
            query = dict(parse_qs(urlparse(context.url).query))
            query[param_name] = payload
            request_data['url'] = f"{context.url.split('?')[0]}?{urlencode(query, doseq=True)}"
            
        elif location == InjectionLocation.BODY:
            if not context.body:
                context.body = {}
                
            if content_type == ContentType.JSON:
                body = context.body.copy()
                # Handle nested JSON paths (e.g. "user.name")
                self._set_nested_value(body, param_name.split('.'), payload)
                request_data['json'] = body
                request_data['headers']['Content-Type'] = ContentType.JSON.value
                
            elif content_type == ContentType.FORM:
                body = context.body.copy()
                body[param_name] = payload
                request_data['data'] = body
                request_data['headers']['Content-Type'] = ContentType.FORM.value
                
            elif content_type == ContentType.XML:
                # Handle XML injection
                if not isinstance(context.body, str):
                    raise ValueError("XML body must be a string")
                request_data['data'] = self._inject_into_xml(context.body, param_name, payload)
                request_data['headers']['Content-Type'] = ContentType.XML.value
                
            elif content_type == ContentType.MULTIPART:
                files = {param_name: (None, payload)}
                request_data['files'] = files
                # Let requests set the correct multipart boundary
                
            else:
                body = context.body.copy()
                body[param_name] = payload
                request_data['json'] = body
                request_data['headers']['Content-Type'] = ContentType.JSON.value
                
        elif location == InjectionLocation.HEADER:
            request_data['headers'][param_name] = payload
            
        elif location == InjectionLocation.COOKIE:
            cookies = context.cookies.copy() if context.cookies else {}
            cookies[param_name] = payload
            request_data['cookies'] = cookies
            
        elif location == InjectionLocation.PATH:
            # Handle path parameter injection
            path_parts = context.url.split('/')
            try:
                param_index = path_parts.index('{' + param_name + '}')
                path_parts[param_index] = quote(payload)
                request_data['url'] = '/'.join(path_parts)
            except ValueError:
                raise ValueError(f"Path parameter {param_name} not found in URL")
                
        return request_data

    def _set_nested_value(self, obj: Dict, path: List[str], value: Any) -> None:
        """Set value in nested dictionary using dot notation path"""
        for i, key in enumerate(path[:-1]):
            if key not in obj:
                obj[key] = {}
            obj = obj[key]
        obj[path[-1]] = value

    def _inject_into_xml(self, xml_str: str, param_name: str, payload: str) -> str:
        """Safely inject payload into XML"""
        try:
            soup = BeautifulSoup(xml_str, 'xml')
            param = soup.find(param_name)
            if param:
                param.string = payload
            else:
                # Create new element if it doesn't exist
                new_elem = soup.new_tag(param_name)
                new_elem.string = payload
                soup.append(new_elem)
            return str(soup)
        except Exception as e:
            raise ValueError(f"Failed to inject into XML: {str(e)}")

    async def _send_request_with_retry(
        self,
        session: Union[requests.Session, aiohttp.ClientSession],
        request_data: Dict[str, Any],
        context: InjectionContext
    ) -> Union[requests.Response, aiohttp.ClientResponse]:
        """Send request with retry logic"""
        last_error = None
        
        for attempt in range(context.retry_count):
            try:
                if isinstance(session, requests.Session):
                    response = await self._send_sync_request(session, request_data)
                else:
                    response = await self._send_async_request(session, request_data)
                    
                return response
                
            except (RequestException, aiohttp.ClientError) as e:
                last_error = e
                if attempt < context.retry_count - 1:
                    delay = context.retry_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(f"Request failed, retrying in {delay}s: {str(e)}")
                    await asyncio.sleep(delay)
                    
        raise last_error or RequestException("Request failed after retries")

    async def _send_sync_request(
        self,
        session: requests.Session,
        request_data: Dict[str, Any]
    ) -> requests.Response:
        """Send synchronous request"""
        method = request_data.pop('method')
        return session.request(method, **request_data)

    async def _send_async_request(
        self,
        session: aiohttp.ClientSession,
        request_data: Dict[str, Any]
    ) -> aiohttp.ClientResponse:
        """Send asynchronous request"""
        method = request_data.pop('method')
        return await session.request(method, **request_data)

    def _add_to_history(self, request_data: Dict[str, Any]) -> None:
        """Add request to history with timestamp"""
        self.request_history.append({
            'timestamp': time.time(),
            'request': request_data,
            'hash': hashlib.sha256(
                json.dumps(request_data, sort_keys=True).encode()
            ).hexdigest()
        })
        
        # Keep only last 1000 requests
        if len(self.request_history) > 1000:
            self.request_history = self.request_history[-1000:]

    def get_request_history(
        self,
        limit: Optional[int] = None,
        filter_func: Optional[callable] = None
    ) -> List[Dict]:
        """Get filtered request history"""
        history = self.request_history
        
        if filter_func:
            history = list(filter(filter_func, history))
            
        if limit:
            history = history[-limit:]
            
        return history
