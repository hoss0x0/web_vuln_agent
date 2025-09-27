import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import yaml
from pathlib import Path
import re
import base64
import hashlib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    XSS = "xss"
    SQLI = "sql_injection"
    CMDI = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "template_injection"
    DESERIALIZATION = "deserialization"
    FILE_INCLUSION = "file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    UNKNOWN = "unknown"

class EncodingType(Enum):
    """Types of payload encoding"""
    BASE64 = "base64"
    URL = "url"
    HTML = "html"
    UNICODE = "unicode"
    HEX = "hex"
    NONE = "none"

class EvasionTechnique(Enum):
    """Types of evasion techniques"""
    CASE_SWITCHING = "case_switching"
    COMMENTS = "comments"
    ENCODING = "encoding"
    CONCATENATION = "concatenation"
    WHITESPACE = "whitespace"
    ALTERNATING = "alternating"
    NONE = "none"

@dataclass
class PayloadMetadata:
    """Structured metadata for security payloads"""
    id: str
    raw_payload: str
    hash: str
    vulnerability_type: VulnerabilityType
    encodings: List[EncodingType]
    evasion_techniques: List[EvasionTechnique]
    intended_effect: str
    risk_level: str
    complexity: str
    detection_difficulty: str
    prerequisites: List[str]
    affected_technologies: List[str]
    mitigation_steps: List[str]
    references: List[str]
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict) -> 'PayloadMetadata':
        """Create PayloadMetadata from dictionary"""
        return cls(
            id=data.get('id', ''),
            raw_payload=data.get('raw_payload', ''),
            hash=data.get('hash', ''),
            vulnerability_type=VulnerabilityType(data.get('vulnerability_type', 'unknown')),
            encodings=[EncodingType(e) for e in data.get('encodings', ['none'])],
            evasion_techniques=[EvasionTechnique(e) for e in data.get('evasion_techniques', ['none'])],
            intended_effect=data.get('intended_effect', ''),
            risk_level=data.get('risk_level', ''),
            complexity=data.get('complexity', ''),
            detection_difficulty=data.get('detection_difficulty', ''),
            prerequisites=data.get('prerequisites', []),
            affected_technologies=data.get('affected_technologies', []),
            mitigation_steps=data.get('mitigation_steps', []),
            references=data.get('references', []),
            timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
            metadata=data.get('metadata', {})
        )

class PayloadAnalyzer:
    """Enhanced payload analyzer with advanced detection features"""
    
    def __init__(self):
        self._load_config()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def _load_config(self) -> None:
        """Load analyzer configuration"""
        try:
            config_path = Path("config/parser_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
                
        except Exception as e:
            logger.error(f"Failed to load analyzer config: {str(e)}")
            self._load_default_config()
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "analysis": {
                "detect_encodings": True,
                "detect_evasion": True,
                "risk_assessment": True,
                "technology_detection": True,
                "reference_lookup": True
            },
            "patterns": {
                "xss": [
                    r"<[^>]*script.*?>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"alert\s*\(",
                ],
                "sqli": [
                    r"(?i)(?:union\s+all|union\s+select)",
                    r"(?i)(?:or|and)\s+\d+\s*=\s*\d+",
                    r"(?i)sleep\s*\(\s*\d+\s*\)",
                ],
                "cmdi": [
                    r"(?:[;|`]|\$\()",
                    r"(?:\|\||&&)",
                ],
            },
            "encodings": {
                "check_nested": True,
                "max_depth": 3
            },
            "cache": {
                "enabled": True,
                "max_size": 1000
            }
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _load_default_config(self) -> None:
        """Load default configuration"""
        self.config = {
            "analysis": {
                "detect_encodings": True,
                "detect_evasion": True
            },
            "patterns": {},
            "encodings": {"max_depth": 3}
        }
        
    def _generate_hash(self, payload: str) -> str:
        """Generate unique hash for payload"""
        return hashlib.sha256(payload.encode()).hexdigest()
        
    def _detect_encodings(self, payload: str, max_depth: int = 3) -> List[EncodingType]:
        """Detect encoding methods used in payload"""
        encodings = set()
        current_payload = payload
        depth = 0
        
        while depth < max_depth:
            # Try base64
            try:
                decoded = base64.b64decode(current_payload)
                if decoded != current_payload.encode():
                    encodings.add(EncodingType.BASE64)
                    current_payload = decoded.decode()
            except:
                pass
                
            # Try URL encoding
            decoded = urllib.parse.unquote(current_payload)
            if decoded != current_payload:
                encodings.add(EncodingType.URL)
                current_payload = decoded
                
            # Try HTML encoding
            if re.search(r"&[#\w]+;", current_payload):
                encodings.add(EncodingType.HTML)
                
            # Try Unicode encoding
            if re.search(r"\\u[0-9a-fA-F]{4}", current_payload):
                encodings.add(EncodingType.UNICODE)
                
            # Try Hex encoding
            if re.search(r"\\x[0-9a-fA-F]{2}", current_payload):
                encodings.add(EncodingType.HEX)
                
            depth += 1
            
        return list(encodings) if encodings else [EncodingType.NONE]
        
    def _detect_evasion(self, payload: str) -> List[EvasionTechnique]:
        """Detect evasion techniques used in payload"""
        techniques = set()
        
        # Case switching
        if re.search(r"(?:[A-Z][a-z])+", payload):
            techniques.add(EvasionTechnique.CASE_SWITCHING)
            
        # Comments
        if re.search(r"/\*.*?\*/|--.*?(?:\n|$)|#.*?(?:\n|$)", payload):
            techniques.add(EvasionTechnique.COMMENTS)
            
        # Encoding
        if any(e != EncodingType.NONE for e in self._detect_encodings(payload)):
            techniques.add(EvasionTechnique.ENCODING)
            
        # String concatenation
        if re.search(r"(?:'|\")\s*\+\s*(?:'|\")", payload):
            techniques.add(EvasionTechnique.CONCATENATION)
            
        # Excessive whitespace
        if re.search(r"\s{2,}|\t+", payload):
            techniques.add(EvasionTechnique.WHITESPACE)
            
        # Alternating patterns
        if re.search(r"(?:[^a-zA-Z]?[a-zA-Z]){3,}", payload):
            techniques.add(EvasionTechnique.ALTERNATING)
            
        return list(techniques) if techniques else [EvasionTechnique.NONE]
        
    def _detect_vulnerability_type(self, payload: str) -> VulnerabilityType:
        """Detect vulnerability type based on patterns"""
        patterns = self.config.get("patterns", {})
        
        for vuln_type, regex_patterns in patterns.items():
            for pattern in regex_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    try:
                        return VulnerabilityType[vuln_type.upper()]
                    except KeyError:
                        continue
                        
        return VulnerabilityType.UNKNOWN
        
    async def analyze_payload(self, payload: str) -> PayloadMetadata:
        """
        Analyze payload and extract comprehensive metadata
        
        Args:
            payload: Raw payload string to analyze
            
        Returns:
            Structured payload metadata
        """
        try:
            # Generate unique ID and hash
            payload_id = hashlib.sha256(payload.encode()).hexdigest()[:8]
            payload_hash = self._generate_hash(payload)
            
            # Detect basic characteristics
            vuln_type = self._detect_vulnerability_type(payload)
            encodings = self._detect_encodings(payload)
            evasion = self._detect_evasion(payload)
            
            # Get advanced analysis from LLM
            query = f"""Analyze the following security payload and provide detailed information:

Payload:
{payload}

Provide:
1. Intended effect and purpose
2. Risk level (Critical/High/Medium/Low)
3. Implementation complexity
4. Detection difficulty
5. Required prerequisites
6. Affected technologies/platforms
7. Mitigation steps
8. Relevant references (CVEs, articles, etc.)

Return a JSON object with these fields.
"""
            
            analysis_result = await self._analyze_with_llm(query)
            
            # Create metadata object
            metadata = PayloadMetadata(
                id=payload_id,
                raw_payload=payload,
                hash=payload_hash,
                vulnerability_type=vuln_type,
                encodings=encodings,
                evasion_techniques=evasion,
                intended_effect=analysis_result.get("intended_effect", ""),
                risk_level=analysis_result.get("risk_level", ""),
                complexity=analysis_result.get("complexity", ""),
                detection_difficulty=analysis_result.get("detection_difficulty", ""),
                prerequisites=analysis_result.get("prerequisites", []),
                affected_technologies=analysis_result.get("affected_technologies", []),
                mitigation_steps=analysis_result.get("mitigation_steps", []),
                references=analysis_result.get("references", []),
                timestamp=datetime.utcnow().isoformat(),
                metadata={
                    "raw_analysis": analysis_result,
                    "detected_patterns": self._detect_patterns(payload)
                }
            )
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to analyze payload: {str(e)}")
            raise
            
    async def _analyze_with_llm(self, query: str) -> Dict:
        """Get analysis from LLM"""
        try:
            result = await self._run_in_thread(generate_response, query)
            return json.loads(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse LLM response as JSON")
            return {}
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            return {}
            
    async def _run_in_thread(self, func, *args):
        """Run function in thread pool"""
        return await self.executor(func, *args)
        
    def _detect_patterns(self, payload: str) -> Dict[str, List[str]]:
        """Detect known patterns in payload"""
        patterns = self.config.get("patterns", {})
        detected = {}
        
        for category, regex_list in patterns.items():
            matches = []
            for pattern in regex_list:
                if found := re.findall(pattern, payload, re.IGNORECASE):
                    matches.extend(found)
            if matches:
                detected[category] = matches
                
        return detected

# Legacy support
async def extract_payload_metadata(payload: str) -> Dict:
    """Legacy wrapper for backward compatibility"""
    analyzer = PayloadAnalyzer()
    metadata = await analyzer.analyze_payload(payload)
    return asdict(metadata)
