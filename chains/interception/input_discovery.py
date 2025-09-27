import json
import logging
import re
from typing import Dict, List, Optional, Set, Union, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse, unquote
import asyncio
from datetime import datetime
import hashlib
from bs4 import BeautifulSoup
import yaml
import jwt

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger
from chains.analysis.detection_heuristics import get_detection_patterns

logger = setup_logger(__name__)

class InputLocationType(Enum):
    """Types of input locations in requests"""
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    MULTIPART = "multipart"
    JSON = "json"
    XML = "xml"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"

class InputType(Enum):
    """Types of input parameters"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    FILE = "file"
    DATE = "date"
    EMAIL = "email"
    URL = "url"
    JSON_DATA = "json"
    XML_DATA = "xml"
    JWT_TOKEN = "jwt"
    BASE64 = "base64"
    CUSTOM = "custom"

@dataclass
class DiscoveredInput:
    """Detailed information about discovered input"""
    name: str
    location: InputLocationType
    value: Any
    input_type: InputType
    metadata: Dict[str, Any]
    context: Dict[str, Any]
    patterns: List[str]
    timestamp: str
    hash: str

class InputDiscoverer:
    """Enhanced input discovery with advanced analysis"""
    
    def __init__(self):
        self._load_config()
        self.detection_patterns = get_detection_patterns()
        self.known_inputs_cache = set()
        self.max_cache_size = 10000
        self.input_history: List[Dict] = []
        
    def _load_config(self) -> None:
        """Load configuration settings"""
        try:
            with open("config/input_discovery.yaml", "r") as f:
                config = yaml.safe_load(f)
                
            self.sensitive_patterns = config.get("sensitive_patterns", [
                r"password",
                r"token",
                r"key",
                r"secret",
                r"auth",
                r"session"
            ])
            
            self.excluded_headers = set(config.get("excluded_headers", [
                "accept",
                "accept-encoding",
                "accept-language",
                "connection",
                "host",
                "user-agent"
            ]))
            
            self.max_input_size = config.get("max_input_size", 8192)
            self.enable_pattern_matching = config.get("enable_pattern_matching", True)
            
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {str(e)}")
            self.sensitive_patterns = []
            self.excluded_headers = set()
            self.max_input_size = 8192
            self.enable_pattern_matching = True
            
    def _detect_input_type(self, value: Any) -> InputType:
        """Detect the type of an input value"""
        if value is None:
            return InputType.STRING
            
        if isinstance(value, bool):
            return InputType.BOOLEAN
            
        if isinstance(value, int):
            return InputType.INTEGER
            
        if isinstance(value, float):
            return InputType.FLOAT
            
        if isinstance(value, (list, tuple)):
            return InputType.ARRAY
            
        if isinstance(value, dict):
            return InputType.OBJECT
            
        if isinstance(value, str):
            # Try to detect special string types
            value = value.strip()
            
            # Check for JSON
            try:
                json.loads(value)
                return InputType.JSON_DATA
            except:
                pass
                
            # Check for XML
            if value.startswith('<?xml') or (value.startswith('<') and value.endswith('>')):
                try:
                    BeautifulSoup(value, 'xml')
                    return InputType.XML_DATA
                except:
                    pass
                    
            # Check for JWT
            try:
                jwt.decode(value, options={"verify_signature": False})
                return InputType.JWT_TOKEN
            except:
                pass
                
            # Check for Base64
            import base64
            try:
                base64.b64decode(value)
                return InputType.BASE64
            except:
                pass
                
            # Check for date
            date_patterns = [
                r'^\d{4}-\d{2}-\d{2}$',
                r'^\d{4}/\d{2}/\d{2}$',
                r'^\d{2}-\d{2}-\d{4}$'
            ]
            if any(re.match(pattern, value) for pattern in date_patterns):
                return InputType.DATE
                
            # Check for email
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                return InputType.EMAIL
                
            # Check for URL
            if re.match(r'^https?://', value):
                return InputType.URL
                
        return InputType.STRING
        
    def _extract_query_params(
        self,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Extract and analyze query parameters"""
        discovered = []
        url = parsed_request.get("url", "")
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for name, values in query_params.items():
                for value in values:
                    input_type = self._detect_input_type(value)
                    
                    # Create unique hash for this input
                    input_hash = hashlib.sha256(
                        f"{url}:{name}:{value}:query".encode()
                    ).hexdigest()
                    
                    discovered.append(DiscoveredInput(
                        name=name,
                        location=InputLocationType.QUERY,
                        value=value,
                        input_type=input_type,
                        metadata={
                            "url": url,
                            "is_sensitive": any(
                                re.search(p, name, re.I)
                                for p in self.sensitive_patterns
                            )
                        },
                        context={
                            "path": parsed_url.path,
                            "method": parsed_request.get("method", "GET")
                        },
                        patterns=self._find_patterns(value),
                        timestamp=datetime.utcnow().isoformat(),
                        hash=input_hash
                    ))
                    
        except Exception as e:
            logger.error(f"Error extracting query params: {str(e)}")
            
        return discovered
        
    def _extract_body_inputs(
        self,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Extract and analyze body parameters"""
        discovered = []
        body = parsed_request.get("body", {})
        content_type = parsed_request.get("headers", {}).get("Content-Type", "")
        
        try:
            if isinstance(body, dict):
                discovered.extend(
                    self._process_dict_body(body, content_type, parsed_request)
                )
            elif isinstance(body, str):
                discovered.extend(
                    self._process_string_body(body, content_type, parsed_request)
                )
                
        except Exception as e:
            logger.error(f"Error extracting body inputs: {str(e)}")
            
        return discovered
        
    def _process_dict_body(
        self,
        body: Dict,
        content_type: str,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Process dictionary body data"""
        discovered = []
        
        def process_dict(d: Dict, prefix: str = ""):
            for key, value in d.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, dict):
                    process_dict(value, full_key)
                elif isinstance(value, (list, tuple)):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            process_dict(item, f"{full_key}[{i}]")
                        else:
                            discovered.append(self._create_body_input(
                                full_key, item, content_type, parsed_request
                            ))
                else:
                    discovered.append(self._create_body_input(
                        full_key, value, content_type, parsed_request
                    ))
                    
        process_dict(body)
        return discovered
        
    def _process_string_body(
        self,
        body: str,
        content_type: str,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Process string body data"""
        discovered = []
        
        if "application/x-www-form-urlencoded" in content_type:
            params = parse_qs(body)
            for name, values in params.items():
                for value in values:
                    discovered.append(self._create_body_input(
                        name, value, content_type, parsed_request
                    ))
                    
        elif "application/json" in content_type:
            try:
                json_data = json.loads(body)
                discovered.extend(
                    self._process_dict_body(json_data, content_type, parsed_request)
                )
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON body")
                
        elif "application/xml" in content_type:
            try:
                soup = BeautifulSoup(body, 'xml')
                for elem in soup.find_all():
                    if elem.string:
                        discovered.append(self._create_body_input(
                            elem.name, elem.string, content_type, parsed_request
                        ))
            except Exception as e:
                logger.warning(f"Failed to parse XML body: {str(e)}")
                
        return discovered
        
    def _create_body_input(
        self,
        name: str,
        value: Any,
        content_type: str,
        parsed_request: Dict
    ) -> DiscoveredInput:
        """Create a body input entry"""
        input_type = self._detect_input_type(value)
        
        # Create unique hash
        input_hash = hashlib.sha256(
            f"{parsed_request.get('url', '')}:{name}:{str(value)}:body".encode()
        ).hexdigest()
        
        return DiscoveredInput(
            name=name,
            location=InputLocationType.BODY,
            value=value,
            input_type=input_type,
            metadata={
                "content_type": content_type,
                "is_sensitive": any(
                    re.search(p, name, re.I)
                    for p in self.sensitive_patterns
                )
            },
            context={
                "method": parsed_request.get("method", "POST"),
                "url": parsed_request.get("url", "")
            },
            patterns=self._find_patterns(str(value)),
            timestamp=datetime.utcnow().isoformat(),
            hash=input_hash
        )
        
    def _extract_header_inputs(
        self,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Extract and analyze header parameters"""
        discovered = []
        headers = parsed_request.get("headers", {})
        
        for name, value in headers.items():
            if name.lower() in self.excluded_headers:
                continue
                
            input_type = self._detect_input_type(value)
            
            # Create unique hash
            input_hash = hashlib.sha256(
                f"{parsed_request.get('url', '')}:{name}:{value}:header".encode()
            ).hexdigest()
            
            discovered.append(DiscoveredInput(
                name=name,
                location=InputLocationType.HEADER,
                value=value,
                input_type=input_type,
                metadata={
                    "is_sensitive": any(
                        re.search(p, name, re.I)
                        for p in self.sensitive_patterns
                    )
                },
                context={
                    "method": parsed_request.get("method", "GET"),
                    "url": parsed_request.get("url", "")
                },
                patterns=self._find_patterns(value),
                timestamp=datetime.utcnow().isoformat(),
                hash=input_hash
            ))
            
        return discovered
        
    def _extract_cookie_inputs(
        self,
        parsed_request: Dict
    ) -> List[DiscoveredInput]:
        """Extract and analyze cookie parameters"""
        discovered = []
        cookies = parsed_request.get("cookies", {})
        
        for name, value in cookies.items():
            input_type = self._detect_input_type(value)
            
            # Create unique hash
            input_hash = hashlib.sha256(
                f"{parsed_request.get('url', '')}:{name}:{value}:cookie".encode()
            ).hexdigest()
            
            discovered.append(DiscoveredInput(
                name=name,
                location=InputLocationType.COOKIE,
                value=value,
                input_type=input_type,
                metadata={
                    "is_sensitive": any(
                        re.search(p, name, re.I)
                        for p in self.sensitive_patterns
                    ),
                    "is_session": "session" in name.lower()
                },
                context={
                    "method": parsed_request.get("method", "GET"),
                    "url": parsed_request.get("url", "")
                },
                patterns=self._find_patterns(value),
                timestamp=datetime.utcnow().isoformat(),
                hash=input_hash
            ))
            
        return discovered
        
    def _find_patterns(self, value: str) -> List[str]:
        """Find matching patterns in input value"""
        if not self.enable_pattern_matching:
            return []
            
        patterns = []
        str_value = str(value)
        
        for vuln_type, type_patterns in self.detection_patterns.items():
            for pattern in type_patterns:
                if re.search(pattern["pattern"], str_value, re.I):
                    patterns.append(f"{vuln_type}: {pattern['pattern']}")
                    
        return patterns
        
    async def discover_inputs_llm(self, parsed_request: Dict) -> List[Dict]:
        """Discover inputs using LLM and heuristic analysis"""
        try:
            # Get heuristic inputs
            heuristic_inputs = []
            heuristic_inputs.extend(self._extract_query_params(parsed_request))
            heuristic_inputs.extend(self._extract_body_inputs(parsed_request))
            heuristic_inputs.extend(self._extract_header_inputs(parsed_request))
            heuristic_inputs.extend(self._extract_cookie_inputs(parsed_request))
            
            # Get LLM inputs
            llm_inputs = await self._get_llm_inputs(parsed_request)
            
            # Combine and deduplicate inputs
            combined_inputs = self._combine_inputs(heuristic_inputs, llm_inputs)
            
            # Update cache and history
            self._update_cache(combined_inputs)
            
            return combined_inputs
            
        except Exception as e:
            logger.error(f"Input discovery failed: {str(e)}")
            return []
            
    async def _get_llm_inputs(self, parsed_request: Dict) -> List[Dict]:
        """Get input analysis from LLM"""
        query = f"""Analyze this HTTP request for all possible user-controllable inputs:

URL: {parsed_request.get('url', '')}
Method: {parsed_request.get('method', 'GET')}
Headers: {json.dumps(parsed_request.get('headers', {}), indent=2)}
Body: {json.dumps(parsed_request.get('body', {}), indent=2)}

Consider:
1. Query parameters
2. Body parameters
3. Headers
4. Cookies
5. Hidden fields
6. Custom formats
7. Encoded values

Return JSON array with objects containing:
- name: parameter name
- location: where found (query/body/header/cookie)
- value: parameter value
- type: detected data type
- notes: any special observations
"""
        try:
            response = generate_response(query)
            return json.loads(response) if isinstance(response, str) else response
        except Exception as e:
            logger.error(f"LLM input discovery failed: {str(e)}")
            return []
            
    def _combine_inputs(
        self,
        heuristic_inputs: List[DiscoveredInput],
        llm_inputs: List[Dict]
    ) -> List[Dict]:
        """Combine and deduplicate inputs from both sources"""
        combined = {}
        
        # Add heuristic inputs
        for input_data in heuristic_inputs:
            combined[input_data.hash] = {
                "name": input_data.name,
                "location": input_data.location.value,
                "value": input_data.value,
                "type": input_data.input_type.value,
                "metadata": input_data.metadata,
                "context": input_data.context,
                "patterns": input_data.patterns,
                "timestamp": input_data.timestamp,
                "source": "heuristic"
            }
            
        # Add LLM inputs
        for llm_input in llm_inputs:
            input_hash = hashlib.sha256(
                f"{llm_input.get('name')}:{llm_input.get('value')}:{llm_input.get('location')}".encode()
            ).hexdigest()
            
            if input_hash not in combined:
                combined[input_hash] = {
                    "name": llm_input.get("name", ""),
                    "location": llm_input.get("location", ""),
                    "value": llm_input.get("value", ""),
                    "type": llm_input.get("type", "string"),
                    "metadata": {"notes": llm_input.get("notes", "")},
                    "context": {},
                    "patterns": [],
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "llm"
                }
            
        return list(combined.values())
        
    def _update_cache(self, inputs: List[Dict]) -> None:
        """Update input cache and history"""
        for input_data in inputs:
            input_hash = hashlib.sha256(
                f"{input_data['name']}:{input_data['value']}:{input_data['location']}".encode()
            ).hexdigest()
            
            self.known_inputs_cache.add(input_hash)
            
            # Maintain cache size
            if len(self.known_inputs_cache) > self.max_cache_size:
                self.known_inputs_cache.pop()
                
            # Add to history
            self.input_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "input": input_data
            })
            
            # Maintain history size
            if len(self.input_history) > self.max_cache_size:
                self.input_history = self.input_history[-self.max_cache_size:]
