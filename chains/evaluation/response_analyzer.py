import json
import re
import logging
import asyncio
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import hashlib
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # Type will be checked before use
from urllib.parse import urlparse, parse_qs

from rag_layer.rag_chain import generate_response
from chains.analysis.detection_heuristics import get_detection_patterns
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Supported vulnerability types for analysis"""
    XSS = "xss"
    SQLI = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"

class ExecutionStatus(Enum):
    """Possible payload execution statuses"""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCERTAIN = "uncertain"
    FAILED = "failed"
    ERROR = "error"

@dataclass
class ResponseIndicator:
    """Indicator found in response analysis"""
    type: str
    pattern: str
    evidence: str
    confidence: float
    location: str
    context: Optional[str] = None

@dataclass
class AnalysisResult:
    """Detailed analysis result"""
    executed: bool
    status: ExecutionStatus
    confidence: float
    indicators: List[ResponseIndicator]
    evidence: List[str]
    notes: List[str]
    response_hash: str
    timestamp: str
    execution_context: Optional[Dict] = None

class ResponseAnalyzer:
    """Enhanced response analyzer with advanced detection features"""

    def __init__(self):
        self.detection_patterns = get_detection_patterns()
        self.min_confidence = 0.7
        self.context_window = 50  # characters before/after match
        
    async def analyze_response(
        self,
        response_text: str,
        payload: str,
        vuln_type: Optional[Union[str, VulnerabilityType]] = None,
        context: Optional[Dict] = None
    ) -> AnalysisResult:
        """
        Analyze response for signs of successful payload execution
        
        Args:
            response_text: HTTP response content
            payload: Injected payload
            vuln_type: Type of vulnerability being tested
            context: Additional context about request/response
            
        Returns:
            AnalysisResult containing detailed analysis
        """
        try:
            # Convert string vuln_type to enum if provided
            if isinstance(vuln_type, str):
                vuln_type = VulnerabilityType(vuln_type.lower())
                
            # Initialize results
            indicators = []
            evidence = []
            notes = []
            
            # Pattern-based analysis
            pattern_indicators = await self._analyze_patterns(
                response_text, payload, vuln_type
            )
            indicators.extend(pattern_indicators)
            
            # Content analysis
            content_indicators = await self._analyze_content(
                response_text, payload, vuln_type
            )
            indicators.extend(content_indicators)
            
            # Error message analysis
            error_indicators = await self._analyze_error_messages(
                response_text, vuln_type
            )
            indicators.extend(error_indicators)
            
            # DOM analysis for XSS
            if vuln_type == VulnerabilityType.XSS:
                dom_indicators = await self._analyze_dom(response_text, payload)
                indicators.extend(dom_indicators)
            
            # Context-based analysis
            if context:
                context_indicators = await self._analyze_context(
                    response_text, context, vuln_type
                )
                indicators.extend(context_indicators)
            
            # LLM-based analysis
            llm_result = await self._llm_analysis(
                response_text, payload, vuln_type
            )
            if llm_result:
                indicators.append(llm_result)
            
            # Calculate confidence and determine execution status
            confidence = self._calculate_confidence(indicators)
            status = self._determine_status(confidence, indicators)
            
            # Collect evidence and notes
            evidence, notes = self._collect_evidence_and_notes(indicators)
            
            # Generate response hash
            response_hash = self._generate_response_hash(response_text)
            
            return AnalysisResult(
                executed=status in [ExecutionStatus.CONFIRMED, ExecutionStatus.LIKELY],
                status=status,
                confidence=confidence,
                indicators=indicators,
                evidence=evidence,
                notes=notes,
                response_hash=response_hash,
                timestamp=datetime.now().isoformat(),
                execution_context=context
            )
            
        except Exception as e:
            logger.error(f"Response analysis failed: {str(e)}")
            return AnalysisResult(
                executed=False,
                status=ExecutionStatus.ERROR,
                confidence=0.0,
                indicators=[],
                evidence=[f"Analysis error: {str(e)}"],
                notes=["Analysis failed due to error"],
                response_hash=self._generate_response_hash(response_text),
                timestamp=datetime.now().isoformat()
            )

    async def _analyze_patterns(
        self, response_text: str, payload: str, vuln_type: Optional[VulnerabilityType]
    ) -> List[ResponseIndicator]:
        """Analyze response using predefined patterns"""
        indicators = []
        
        patterns = self.detection_patterns.get(
            vuln_type.value if vuln_type else "general", []
        )
        
        for pattern in patterns:
            matches = re.finditer(pattern["regex"], response_text, re.I | re.M)
            for match in matches:
                # Get context around match
                start = max(0, match.start() - self.context_window)
                end = min(len(response_text), match.end() + self.context_window)
                context = response_text[start:end]
                
                indicators.append(ResponseIndicator(
                    type="pattern_match",
                    pattern=pattern["regex"],
                    evidence=match.group(0),
                    confidence=1.0 - pattern.get("false_positive_rate", 0.5),
                    location=f"offset {match.start()}",
                    context=context
                ))
                
        return indicators

    async def _analyze_content(
        self, response_text: str, payload: str, vuln_type: Optional[VulnerabilityType]
    ) -> List[ResponseIndicator]:
        """Analyze response content for payload execution signs"""
        indicators = []
        
        # Check for exact payload reflection
        if payload in response_text:
            # Find all occurrences
            for match in re.finditer(re.escape(payload), response_text):
                start = max(0, match.start() - self.context_window)
                end = min(len(response_text), match.end() + self.context_window)
                context = response_text[start:end]
                
                indicators.append(ResponseIndicator(
                    type="payload_reflection",
                    pattern="exact_match",
                    evidence=payload,
                    confidence=0.8,
                    location=f"offset {match.start()}",
                    context=context
                ))
        
        # Check for encoded versions
        encoded_payloads = [
            (payload.encode('base64').decode(), "base64"),
            (payload.encode('hex').decode(), "hex"),
            # Add more encodings
        ]
        
        for encoded, encoding in encoded_payloads:
            if encoded in response_text:
                indicators.append(ResponseIndicator(
                    type="encoded_payload",
                    pattern=f"{encoding}_encoded",
                    evidence=encoded,
                    confidence=0.6,
                    location=f"encoded_{encoding}"
                ))
        
        return indicators

    async def _analyze_error_messages(
        self, response_text: str, vuln_type: Optional[VulnerabilityType]
    ) -> List[ResponseIndicator]:
        """Analyze response for error messages indicating successful exploitation"""
        indicators = []
        
        error_patterns = {
            VulnerabilityType.SQLI: [
                r"SQL syntax.*MySQL",
                r"Warning.*SQLite3::",
                r"PostgreSQL.*ERROR",
                r"ORA-[0-9][0-9][0-9][0-9]",
            ],
            VulnerabilityType.XSS: [
                r"<script>.*</script>",
                r"onerror=",
                r"javascript:",
            ],
            # Add more patterns for other vulnerability types
        }
        
        if vuln_type and vuln_type in error_patterns:
            for pattern in error_patterns[vuln_type]:
                matches = re.finditer(pattern, response_text, re.I | re.M)
                for match in matches:
                    indicators.append(ResponseIndicator(
                        type="error_pattern",
                        pattern=pattern,
                        evidence=match.group(0),
                        confidence=0.7,
                        location=f"offset {match.start()}"
                    ))
                    
        return indicators

    async def _analyze_dom(
        self, response_text: str, payload: str
    ) -> List[ResponseIndicator]:
        """Analyze DOM structure for XSS payload execution"""
        indicators = []
        
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Look for script tags
            for script in soup.find_all('script'):
                if payload in script.string:
                    indicators.append(ResponseIndicator(
                        type="dom_script",
                        pattern="script_tag",
                        evidence=script.string,
                        confidence=0.9,
                        location="script_tag"
                    ))
            
            # Look for event handlers
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith('on') and payload in tag[attr]:
                        indicators.append(ResponseIndicator(
                            type="dom_event",
                            pattern="event_handler",
                            evidence=f"{attr}={tag[attr]}",
                            confidence=0.8,
                            location=f"tag_{tag.name}"
                        ))
                        
        except Exception as e:
            logger.warning(f"DOM analysis failed: {str(e)}")
            
        return indicators

    async def _analyze_context(
        self, response_text: str, context: Dict, vuln_type: Optional[VulnerabilityType]
    ) -> List[ResponseIndicator]:
        """Analyze response in the context of the request"""
        indicators = []
        
        # Check response code patterns
        if status_code := context.get("status_code"):
            if status_code >= 500:
                indicators.append(ResponseIndicator(
                    type="status_code",
                    pattern="server_error",
                    evidence=f"Status code {status_code}",
                    confidence=0.6,
                    location="response_status"
                ))
        
        # Check content type
        if content_type := context.get("content_type"):
            expected_types = {
                VulnerabilityType.XSS: ["text/html", "application/javascript"],
                VulnerabilityType.SQLI: ["text/html", "application/json"],
                # Add more type mappings
            }
            
            if vuln_type and vuln_type in expected_types:
                if content_type in expected_types[vuln_type]:
                    indicators.append(ResponseIndicator(
                        type="content_type",
                        pattern="expected_type",
                        evidence=content_type,
                        confidence=0.5,
                        location="response_headers"
                    ))
        
        return indicators

    async def _llm_analysis(
        self, response_text: str, payload: str, vuln_type: Optional[VulnerabilityType]
    ) -> Optional[ResponseIndicator]:
        """Use LLM to analyze response"""
        try:
            query = f"""Analyze the following HTTP response for signs of successful payload execution.

Vulnerability type: {vuln_type.value if vuln_type else 'unknown'}
Payload: {payload}

Response:
{response_text}

Consider:
1. Direct payload execution evidence
2. Error messages or warnings
3. Response structure changes
4. Suspicious patterns
5. Security implications

Return JSON with fields:
- executed (boolean)
- confidence (float 0-1)
- evidence (string)
- reasoning (string)
"""
            result = generate_response(query)
            
            try:
                parsed = json.loads(result) if isinstance(result, str) else result
                return ResponseIndicator(
                    type="llm_analysis",
                    pattern="semantic_analysis",
                    evidence=parsed.get("evidence", "No specific evidence"),
                    confidence=float(parsed.get("confidence", 0.5)),
                    location="full_response",
                    context=parsed.get("reasoning")
                )
            except (json.JSONDecodeError, ValueError):
                logger.warning("Failed to parse LLM response")
                return None
                
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            return None

    def _calculate_confidence(self, indicators: List[ResponseIndicator]) -> float:
        """Calculate overall confidence from indicators"""
        if not indicators:
            return 0.0
            
        # Weight different indicator types
        weights = {
            "pattern_match": 0.3,
            "payload_reflection": 0.2,
            "error_pattern": 0.15,
            "dom_script": 0.4,
            "dom_event": 0.3,
            "status_code": 0.1,
            "content_type": 0.1,
            "llm_analysis": 0.2
        }
        
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for indicator in indicators:
            weight = weights.get(indicator.type, 0.1)
            weighted_sum += indicator.confidence * weight
            weight_sum += weight
            
        return weighted_sum / weight_sum if weight_sum > 0 else 0.0

    def _determine_status(
        self, confidence: float, indicators: List[ResponseIndicator]
    ) -> ExecutionStatus:
        """Determine execution status based on confidence and indicators"""
        if confidence >= 0.8 and any(i.type in ["dom_script", "pattern_match"] for i in indicators):
            return ExecutionStatus.CONFIRMED
        elif confidence >= 0.6:
            return ExecutionStatus.LIKELY
        elif confidence >= 0.3:
            return ExecutionStatus.UNCERTAIN
        else:
            return ExecutionStatus.FAILED

    def _collect_evidence_and_notes(
        self, indicators: List[ResponseIndicator]
    ) -> Tuple[List[str], List[str]]:
        """Collect evidence and notes from indicators"""
        evidence = []
        notes = []
        
        for indicator in indicators:
            if indicator.evidence:
                evidence.append(f"{indicator.type}: {indicator.evidence}")
            if indicator.context:
                notes.append(f"{indicator.type} context: {indicator.context}")
                
        return evidence, notes

    def _generate_response_hash(self, response_text: str) -> str:
        """Generate hash of response content"""
        return hashlib.sha256(response_text.encode()).hexdigest()

def analyze_response_llm(response_text: str, payload: str) -> Dict:
    """Legacy wrapper for backward compatibility"""
    analyzer = ResponseAnalyzer()
    result = asyncio.run(analyzer.analyze_response(response_text, payload))
    return {
        "executed": result.executed,
        "evidence": result.evidence,
        "notes": result.notes
    }
