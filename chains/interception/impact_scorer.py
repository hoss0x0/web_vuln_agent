import json
import logging
import re
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import asyncio
from datetime import datetime
import hashlib
from urllib.parse import urlparse, parse_qs

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Types of vulnerabilities to check for"""
    XSS = "xss"
    SQLI = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    FILE_INCLUSION = "file_inclusion"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    TEMPLATE_INJECTION = "template_injection"

@dataclass
class InputContext:
    """Context information for input analysis"""
    url: str
    method: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    path_params: Dict[str, str]
    query_params: Dict[str, str]
    body_params: Dict[str, str]
    content_type: Optional[str] = None
    referer: Optional[str] = None
    origin: Optional[str] = None

@dataclass
class InputData:
    """Detailed input information"""
    name: str
    value: str
    location: str
    param_type: Optional[str] = None
    encoding: Optional[str] = None
    is_reflected: bool = False
    context_data: Optional[Dict] = None

@dataclass
class VulnerabilityScore:
    """Comprehensive vulnerability scoring"""
    input_name: str
    location: str
    value: str
    base_score: float
    impact_score: float
    likelihood_score: float
    context_score: float
    final_score: float
    vulnerability_types: List[VulnerabilityType]
    evidence: List[str]
    timestamp: str
    risk_factors: Dict[str, float]

class ImpactScorer:
    """Enhanced impact scoring with advanced analysis"""

    def __init__(self):
        self.dangerous_patterns = self._load_dangerous_patterns()
        self.context_weights = self._load_context_weights()
        self.cache = {}
        self.min_score_threshold = 0.5
        self.max_cache_size = 1000
        
    def _load_dangerous_patterns(self) -> Dict[VulnerabilityType, List[Dict]]:
        """Load patterns for vulnerability detection"""
        return {
            VulnerabilityType.XSS: [
                {"pattern": r"[<>]|javascript:|on\w+\s*=", "weight": 0.8},
                {"pattern": r"data:|vbscript:|expression\s*\(", "weight": 0.7}
            ],
            VulnerabilityType.SQLI: [
                {"pattern": r"'\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)\s", "weight": 0.9},
                {"pattern": r"--|\#|\/\*|\*\/|;", "weight": 0.7}
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                {"pattern": r"[&;`|]|\$\(|\|\||&&", "weight": 0.9},
                {"pattern": r">\s*[^>]", "weight": 0.8}
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                {"pattern": r"\.\.\/|\.\.\\", "weight": 0.8},
                {"pattern": r"^\/(?:etc|var|usr|root)", "weight": 0.7}
            ],
            VulnerabilityType.SSRF: [
                {"pattern": r"https?:\/\/|file:\/\/|dict:\/\/|gopher:\/\/", "weight": 0.8},
                {"pattern": r"localhost|127\.0\.0\.1|0\.0\.0\.0", "weight": 0.9}
            ],
            # Add more vulnerability patterns
        }
        
    def _load_context_weights(self) -> Dict[str, float]:
        """Load weights for context-based scoring"""
        return {
            "cookie": 0.9,  # High-risk context
            "header": 0.8,  # Security-sensitive
            "body": 0.7,    # User-controlled
            "query": 0.6,   # Easily modified
            "path": 0.5     # Part of URL
        }
        
    def _calculate_base_score(self, input_data: InputData) -> float:
        """Calculate base vulnerability score"""
        score = 0.0
        found_patterns = []
        
        # Check against all vulnerability patterns
        for vuln_type, patterns in self.dangerous_patterns.items():
            for pattern in patterns:
                if re.search(pattern["pattern"], input_data.value, re.I):
                    score += pattern["weight"]
                    found_patterns.append(f"{vuln_type.value}: {pattern['pattern']}")
                    
        # Normalize score
        return min(score, 5.0)
        
    def _calculate_impact_score(
        self,
        input_data: InputData,
        context: InputContext
    ) -> Tuple[float, List[str]]:
        """Calculate potential impact score"""
        impact_factors = []
        score = 0.0
        
        # Check for sensitive contexts
        if input_data.location == "cookie" and "session" in input_data.name.lower():
            score += 1.0
            impact_factors.append("Session cookie manipulation")
            
        if input_data.location == "header" and "authorization" in input_data.name.lower():
            score += 1.0
            impact_factors.append("Authorization header manipulation")
            
        # Check for dangerous content types
        if context.content_type:
            if "json" in context.content_type.lower():
                score += 0.5
                impact_factors.append("JSON content type")
            elif "xml" in context.content_type.lower():
                score += 0.8
                impact_factors.append("XML content type - potential XXE")
                
        # Check for dangerous operations
        if context.method in ["POST", "PUT", "DELETE"]:
            score += 0.5
            impact_factors.append(f"Dangerous HTTP method: {context.method}")
            
        # Check for file operations
        if any(word in input_data.name.lower() for word in ["file", "path", "upload", "download"]):
            score += 0.8
            impact_factors.append("File operation parameter")
            
        return min(score, 5.0), impact_factors
        
    def _calculate_likelihood_score(
        self,
        input_data: InputData,
        context: InputContext
    ) -> Tuple[float, List[str]]:
        """Calculate likelihood of successful exploitation"""
        likelihood_factors = []
        score = 0.0
        
        # Check for lack of encoding
        if not input_data.encoding:
            score += 0.5
            likelihood_factors.append("No input encoding")
            
        # Check for reflection
        if input_data.is_reflected:
            score += 1.0
            likelihood_factors.append("Input is reflected in response")
            
        # Check for common security headers
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        
        missing_headers = [h for h in security_headers if h not in context.headers]
        if missing_headers:
            score += 0.5
            likelihood_factors.append(f"Missing security headers: {', '.join(missing_headers)}")
            
        return min(score, 5.0), likelihood_factors
        
    def _calculate_context_score(
        self,
        input_data: InputData,
        context: InputContext
    ) -> Tuple[float, List[str]]:
        """Calculate context-based risk score"""
        context_factors = []
        score = 0.0
        
        # Apply context weights
        if input_data.location in self.context_weights:
            score += self.context_weights[input_data.location]
            context_factors.append(f"High-risk location: {input_data.location}")
            
        # Check for sensitive endpoints
        sensitive_paths = ["admin", "api", "auth", "login", "upload"]
        path = urlparse(context.url).path.lower()
        if any(s in path for s in sensitive_paths):
            score += 0.8
            context_factors.append(f"Sensitive endpoint: {path}")
            
        # Check cross-origin context
        if context.origin and context.referer:
            if urlparse(context.origin).netloc != urlparse(context.referer).netloc:
                score += 0.6
                context_factors.append("Cross-origin request")
                
        return min(score, 5.0), context_factors
        
    def _detect_vulnerability_types(
        self,
        input_data: InputData,
        base_score: float
    ) -> List[VulnerabilityType]:
        """Detect potential vulnerability types"""
        vuln_types = []
        
        for vuln_type, patterns in self.dangerous_patterns.items():
            if any(
                re.search(p["pattern"], input_data.value, re.I)
                for p in patterns
            ):
                vuln_types.append(vuln_type)
                
        return vuln_types
        
    async def score_input(
        self,
        input_data: InputData,
        context: InputContext
    ) -> VulnerabilityScore:
        """Score a single input for vulnerability potential"""
        try:
            # Generate cache key
            cache_key = hashlib.md5(
                f"{input_data.name}:{input_data.value}:{input_data.location}".encode()
            ).hexdigest()
            
            # Check cache
            if cache_key in self.cache:
                return self.cache[cache_key]
                
            # Calculate component scores
            base_score = self._calculate_base_score(input_data)
            impact_score, impact_factors = self._calculate_impact_score(input_data, context)
            likelihood_score, likelihood_factors = self._calculate_likelihood_score(input_data, context)
            context_score, context_factors = self._calculate_context_score(input_data, context)
            
            # Calculate final score
            final_score = (
                base_score * 0.4 +
                impact_score * 0.3 +
                likelihood_score * 0.2 +
                context_score * 0.1
            )
            
            # Detect vulnerability types
            vuln_types = self._detect_vulnerability_types(input_data, base_score)
            
            # Create comprehensive score result
            score = VulnerabilityScore(
                input_name=input_data.name,
                location=input_data.location,
                value=input_data.value,
                base_score=base_score,
                impact_score=impact_score,
                likelihood_score=likelihood_score,
                context_score=context_score,
                final_score=final_score,
                vulnerability_types=vuln_types,
                evidence=impact_factors + likelihood_factors + context_factors,
                timestamp=datetime.utcnow().isoformat(),
                risk_factors={
                    "base": base_score / 5.0,
                    "impact": impact_score / 5.0,
                    "likelihood": likelihood_score / 5.0,
                    "context": context_score / 5.0
                }
            )
            
            # Cache result
            self.cache[cache_key] = score
            
            # Maintain cache size
            if len(self.cache) > self.max_cache_size:
                self.cache.pop(next(iter(self.cache)))
                
            return score
            
        except Exception as e:
            logger.error(f"Error scoring input {input_data.name}: {str(e)}")
            raise
            
    async def score_inputs_llm(
        self,
        parsed_request: Dict,
        inputs: List[Dict]
    ) -> List[Dict]:
        """Score inputs using LLM and heuristic analysis"""
        try:
            # Prepare context
            context = InputContext(
                url=parsed_request.get("url", ""),
                method=parsed_request.get("method", "GET"),
                headers=parsed_request.get("headers", {}),
                cookies=parsed_request.get("cookies", {}),
                path_params=parsed_request.get("path_params", {}),
                query_params=parsed_request.get("query_params", {}),
                body_params=parsed_request.get("body_params", {}),
                content_type=parsed_request.get("headers", {}).get("Content-Type"),
                referer=parsed_request.get("headers", {}).get("Referer"),
                origin=parsed_request.get("headers", {}).get("Origin")
            )
            
            # Process each input
            results = []
            for input_item in inputs:
                input_data = InputData(
                    name=input_item.get("name", ""),
                    value=input_item.get("value", ""),
                    location=input_item.get("location", ""),
                    param_type=input_item.get("type"),
                    encoding=input_item.get("encoding"),
                    is_reflected=input_item.get("is_reflected", False),
                    context_data=input_item.get("context", {})
                )
                
                # Get heuristic score
                score = await self.score_input(input_data, context)
                
                # Get LLM score
                llm_score = await self._get_llm_score(input_data, context)
                
                # Combine scores
                combined_score = self._combine_scores(score, llm_score)
                results.append(combined_score)
                
            return results
            
        except Exception as e:
            logger.error(f"Error in LLM scoring: {str(e)}")
            return []
            
    async def _get_llm_score(
        self,
        input_data: InputData,
        context: InputContext
    ) -> Dict:
        """Get vulnerability score from LLM"""
        query = f"""Analyze this input for security vulnerabilities:

Input Name: {input_data.name}
Value: {input_data.value}
Location: {input_data.location}
Method: {context.method}
Content-Type: {context.content_type}

Consider:
1. Potential vulnerability types
2. Impact severity
3. Exploitation likelihood
4. Security context
5. Common attack patterns

Return JSON with:
- score (0-5)
- vulnerability_types (list)
- reasoning (string)
- confidence (0-1)
"""
        try:
            response = generate_response(query)
            return json.loads(response) if isinstance(response, str) else response
        except Exception as e:
            logger.error(f"LLM scoring failed: {str(e)}")
            return {
                "score": 0,
                "vulnerability_types": [],
                "reasoning": "LLM analysis failed",
                "confidence": 0
            }
            
    def _combine_scores(
        self,
        heuristic_score: VulnerabilityScore,
        llm_score: Dict
    ) -> Dict:
        """Combine heuristic and LLM scores"""
        return {
            "name": heuristic_score.input_name,
            "location": heuristic_score.location,
            "value": heuristic_score.value,
            "heuristic_score": heuristic_score.final_score,
            "llm_score": llm_score.get("score", 0),
            "combined_score": (
                heuristic_score.final_score * 0.7 +
                llm_score.get("score", 0) * 0.3
            ),
            "vulnerability_types": [
                vt.value for vt in heuristic_score.vulnerability_types
            ] + llm_score.get("vulnerability_types", []),
            "evidence": heuristic_score.evidence,
            "llm_reasoning": llm_score.get("reasoning", ""),
            "confidence": llm_score.get("confidence", 0),
            "risk_factors": heuristic_score.risk_factors,
            "timestamp": heuristic_score.timestamp
        }
