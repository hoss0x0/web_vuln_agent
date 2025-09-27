import json
import logging
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import re
from urllib.parse import urlparse, parse_qs, unquote, urljoin
import xml.etree.ElementTree as ET
from datetime import datetime
import hashlib
from bs4 import BeautifulSoup
import yaml
import base64
from multipart import parse_multipart

from utils.logger import setup_logger

logger = setup_logger(__name__)

class ContentType(Enum):
    """Supported content types"""
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    TEXT = "text/plain"
    HTML = "text/html"
    GRAPHQL = "application/graphql"
    PROTO = "application/protobuf"
    CUSTOM = "custom"

@dataclass
class ParsedRequest:
    """Structured representation of parsed request"""
    method: str
    url: str
    protocol: str
    host: str
    port: Optional[int]
    path: str
    query_string: str
    query_params: Dict[str, List[str]]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: Any
    body_type: ContentType
    content_length: int
    is_secure: bool
    timestamp: str
    hash: str
    metadata: Dict[str, Any]

class RequestParser:
    """Enhanced request parser with advanced features"""
    
    def __init__(self):
        self._load_config()
        self.parsed_cache = {}
        self.max_cache_size = 1000
        
    def _load_config(self) -> None:
        """Load parser configuration"""
        try:
            with open("config/parser_config.yaml", "r") as f:
                config = yaml.safe_load(f)
                
            self.max_body_size = config.get("max_body_size", 10 * 1024 * 1024)  # 10MB
            self.allowed_methods = set(config.get("allowed_methods", [
                "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
            ]))
            self.decode_base64 = config.get("decode_base64", True)
            self.parse_cookies = config.get("parse_cookies", True)
            self.validate_content_length = config.get("validate_content_length", True)
            self.max_query_params = config.get("max_query_params", 100)
            
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {str(e)}")
            self.max_body_size = 10 * 1024 * 1024
            self.allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
            self.decode_base64 = True
            self.parse_cookies = True
            self.validate_content_length = True
            self.max_query_params = 100
            
    def parse_request(self, raw: Dict) -> ParsedRequest:
        """Parse raw request into structured format"""
        try:
            # Generate request hash
            request_hash = self._generate_request_hash(raw)
            
            # Check cache
            if request_hash in self.parsed_cache:
                return self.parsed_cache[request_hash]
                
            # Basic validation
            self._validate_request(raw)
            
            # Parse URL components
            url_components = self._parse_url(raw.get("url", ""))
            
            # Parse headers
            headers = self._parse_headers(raw.get("headers", {}))
            
            # Parse cookies
            cookies = self._parse_cookies(headers) if self.parse_cookies else {}
            
            # Parse body
            body, body_type = self._parse_body(
                raw.get("body", ""),
                headers.get("Content-Type", "")
            )
            
            # Create parsed request
            parsed = ParsedRequest(
                method=raw.get("method", "GET").upper(),
                url=raw.get("url", ""),
                protocol=url_components["protocol"],
                host=url_components["host"],
                port=url_components["port"],
                path=url_components["path"],
                query_string=url_components["query_string"],
                query_params=url_components["query_params"],
                headers=headers,
                cookies=cookies,
                body=body,
                body_type=body_type,
                content_length=self._get_content_length(headers, body),
                is_secure=url_components["protocol"] == "https",
                timestamp=datetime.utcnow().isoformat(),
                hash=request_hash,
                metadata=self._generate_metadata(raw)
            )
            
            # Cache result
            self._update_cache(request_hash, parsed)
            
            return parsed
            
        except Exception as e:
            logger.error(f"Request parsing failed: {str(e)}")
            raise
            
    def _validate_request(self, raw: Dict) -> None:
        """Validate raw request data"""
        if not isinstance(raw, dict):
            raise ValueError("Request must be a dictionary")
            
        method = raw.get("method", "GET").upper()
        if method not in self.allowed_methods:
            raise ValueError(f"Unsupported HTTP method: {method}")
            
        url = raw.get("url", "")
        if not url:
            raise ValueError("URL is required")
            
        try:
            urlparse(url)
        except Exception:
            raise ValueError("Invalid URL format")
            
        headers = raw.get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("Headers must be a dictionary")
            
        body = raw.get("body", "")
        if self.validate_content_length:
            content_length = len(str(body).encode())
            if content_length > self.max_body_size:
                raise ValueError(f"Body size exceeds limit: {content_length} > {self.max_body_size}")
                
    def _parse_url(self, url: str) -> Dict[str, Any]:
        """Parse URL into components"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Validate query params count
        if len(query_params) > self.max_query_params:
            raise ValueError(f"Too many query parameters: {len(query_params)} > {self.max_query_params}")
            
        # Parse port
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == "https" else 80
            
        return {
            "protocol": parsed.scheme,
            "host": parsed.hostname or "",
            "port": port,
            "path": parsed.path,
            "query_string": parsed.query,
            "query_params": query_params,
            "fragment": parsed.fragment
        }
        
    def _parse_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parse and normalize headers"""
        normalized = {}
        
        for key, value in headers.items():
            # Normalize header names
            normalized_key = "-".join(
                word.capitalize() for word in key.split("-")
            )
            normalized[normalized_key] = str(value)
            
        return normalized
        
    def _parse_cookies(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parse cookies from headers"""
        cookies = {}
        cookie_header = headers.get("Cookie", "")
        
        if cookie_header:
            pairs = cookie_header.split(";")
            for pair in pairs:
                if "=" in pair:
                    key, value = pair.strip().split("=", 1)
                    cookies[key] = unquote(value)
                    
        return cookies
        
    def _parse_body(
        self,
        body: Any,
        content_type: str
    ) -> Tuple[Any, ContentType]:
        """Parse request body based on content type"""
        if not body:
            return None, ContentType.TEXT
            
        # Handle string body
        if isinstance(body, str):
            body = body.strip()
            
            # Try JSON
            if "application/json" in content_type:
                try:
                    return json.loads(body), ContentType.JSON
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON body: {str(e)}")
                    return body, ContentType.TEXT
                    
            # Try URL-encoded form
            elif "application/x-www-form-urlencoded" in content_type:
                return dict(parse_qs(body)), ContentType.FORM
                
            # Try XML
            elif "application/xml" in content_type or "text/xml" in content_type:
                try:
                    return ET.fromstring(body), ContentType.XML
                except ET.ParseError as e:
                    logger.warning(f"Failed to parse XML body: {str(e)}")
                    return body, ContentType.TEXT
                    
            # Try multipart
            elif "multipart/form-data" in content_type:
                try:
                    boundary = content_type.split("boundary=")[1]
                    return parse_multipart(body, boundary), ContentType.MULTIPART
                except Exception as e:
                    logger.warning(f"Failed to parse multipart body: {str(e)}")
                    return body, ContentType.TEXT
                    
            # Try base64
            elif self.decode_base64:
                try:
                    decoded = base64.b64decode(body).decode()
                    # Try parsing decoded content as JSON
                    try:
                        return json.loads(decoded), ContentType.JSON
                    except:
                        return decoded, ContentType.TEXT
                except:
                    pass
                    
        # Handle dict/list body
        elif isinstance(body, (dict, list)):
            return body, ContentType.JSON
            
        return body, ContentType.TEXT
        
    def _get_content_length(self, headers: Dict[str, str], body: Any) -> int:
        """Calculate actual content length"""
        if not body:
            return 0
            
        if isinstance(body, (str, bytes)):
            return len(body)
        else:
            return len(json.dumps(body))
            
    def _generate_request_hash(self, raw: Dict) -> str:
        """Generate unique hash for request"""
        components = [
            raw.get("method", ""),
            raw.get("url", ""),
            json.dumps(raw.get("headers", {}), sort_keys=True),
            str(raw.get("body", ""))
        ]
        return hashlib.sha256(
            "|".join(components).encode()
        ).hexdigest()
        
    def _generate_metadata(self, raw: Dict) -> Dict[str, Any]:
        """Generate request metadata"""
        return {
            "raw_size": len(str(raw).encode()),
            "has_body": bool(raw.get("body")),
            "has_query": bool(urlparse(raw.get("url", "")).query),
            "header_count": len(raw.get("headers", {})),
            "cookie_count": len(self._parse_cookies(raw.get("headers", {}))),
            "parsed_timestamp": datetime.utcnow().isoformat()
        }
        
    def _update_cache(self, request_hash: str, parsed: ParsedRequest) -> None:
        """Update parser cache"""
        self.parsed_cache[request_hash] = parsed
        
        # Maintain cache size
        if len(self.parsed_cache) > self.max_cache_size:
            oldest_key = next(iter(self.parsed_cache))
            del self.parsed_cache[oldest_key]
