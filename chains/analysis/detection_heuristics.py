import json
import re
import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Supported vulnerability types for detection"""
    XSS = "xss"
    SQLI = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"

@dataclass
class DetectionPattern:
    """Pattern definition for vulnerability detection"""
    regex: str
    description: str
    severity: str
    false_positive_rate: float
    context_required: bool = False

class VulnerabilityDetector:
    """Enhanced vulnerability detection with multiple heuristics"""

    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.min_confidence = 0.7

    def _initialize_patterns(self) -> Dict[str, List[DetectionPattern]]:
        """Initialize detection patterns for different vulnerability types"""
        return {
            "xss": [
                DetectionPattern(
                    regex=r"<script[\s\S]*?>[\s\S]*?</script>",
                    description="Found script tag execution",
                    severity="high",
                    false_positive_rate=0.1
                ),
                DetectionPattern(
                    regex=r"(?i)javascript:|on\w+\s*=|data:text/javascript",
                    description="Detected JavaScript event handlers or protocol",
                    severity="medium",
                    false_positive_rate=0.2
                ),
                DetectionPattern(
                    regex=r"(?i)alert\s*\(|confirm\s*\(|prompt\s*\(",
                    description="JavaScript dialog function execution",
                    severity="high",
                    false_positive_rate=0.1
                )
            ],
            "sql_injection": [
                DetectionPattern(
                    regex=r"(?i)(SQL syntax.*MySQL|Warning.*SQLite3|PostgreSQL.*ERROR|ORA-[0-9][0-9][0-9][0-9]|Microsoft SQL|ODBC Driver)",
                    description="Database error message detected",
                    severity="high",
                    false_positive_rate=0.05
                ),
                DetectionPattern(
                    regex=r"(?i)(AND|OR)\s+\d+\s*=\s*\d+|UNION\s+(ALL\s+)?SELECT",
                    description="SQL injection pattern detected",
                    severity="critical",
                    false_positive_rate=0.1
                )
            ],
            "command_injection": [
                DetectionPattern(
                    regex=r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ)",
                    description="System file access attempted",
                    severity="critical",
                    false_positive_rate=0.05,
                    context_required=True
                ),
                DetectionPattern(
                    regex=r"(?i)(root:x:|Directory listing|Volume Serial Number)",
                    description="Command output detected",
                    severity="high",
                    false_positive_rate=0.15
                )
            ],
            "path_traversal": [
                DetectionPattern(
                    regex=r"(?i)root:x:|boot loader|win.ini|system32",
                    description="System file content detected",
                    severity="high",
                    false_positive_rate=0.1
                )
            ],
            "file_inclusion": [
                DetectionPattern(
                    regex=r"(?i)(<\?php|<%|<asp|<jsp)",
                    description="Server-side code execution detected",
                    severity="critical",
                    false_positive_rate=0.1
                )
            ],
            "xxe": [
                DetectionPattern(
                    regex=r"(?i)(!DOCTYPE|ENTITY.*SYSTEM|<!ENTITY)",
                    description="XML entity declaration detected",
                    severity="critical",
                    false_positive_rate=0.05,
                    context_required=True
                )
            ]
        }

    def detect_vulnerability(
        self,
        response_text: str,
        payload: str,
        vuln_type: Union[str, VulnerabilityType],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Detect vulnerability using multiple detection methods
        
        Args:
            response_text: HTTP response text
            payload: Injected payload
            vuln_type: Type of vulnerability to detect
            context: Additional context about the request/response
            
        Returns:
            Dictionary containing detection results and analysis
        """
        try:
            # Convert string vuln_type to enum if needed
            if isinstance(vuln_type, str):
                vuln_type = VulnerabilityType(vuln_type.lower())

            # Initialize results
            results = {
                "detected": False,
                "confidence": 0.0,
                "evidence": [],
                "severity": "none",
                "false_positives": [],
                "analysis": []
            }

            # Pattern-based detection
            pattern_results = self._pattern_based_detection(
                response_text, vuln_type.value
            )
            results["evidence"].extend(pattern_results["evidence"])
            results["false_positives"].extend(pattern_results["false_positives"])

            # Payload reflection analysis
            reflection_results = self._analyze_payload_reflection(
                response_text, payload, vuln_type
            )
            results["evidence"].extend(reflection_results["evidence"])

            # Context-based detection
            if context:
                context_results = self._context_based_detection(
                    response_text, context, vuln_type
                )
                results["evidence"].extend(context_results["evidence"])

            # LLM-based detection
            llm_results = self._llm_based_detection(
                response_text, payload, vuln_type
            )
            if llm_results["detected"]:
                results["evidence"].append(llm_results["reason"])

            # Calculate final confidence
            results["confidence"] = self._calculate_confidence(
                pattern_results, reflection_results, context_results if context else None, llm_results
            )

            # Set detection status and severity
            results["detected"] = results["confidence"] >= self.min_confidence
            results["severity"] = self._determine_severity(results["evidence"])

            # Generate analysis summary
            results["analysis"] = self._generate_analysis(results)

            return results

        except Exception as e:
            logger.error(f"Error in vulnerability detection: {str(e)}")
            return {
                "detected": False,
                "confidence": 0.0,
                "evidence": [],
                "severity": "error",
                "false_positives": [],
                "analysis": [f"Error during detection: {str(e)}"]
            }

    def _pattern_based_detection(self, response_text: str, vuln_type: str) -> Dict:
        """Detect vulnerability using predefined patterns"""
        results = {
            "evidence": [],
            "false_positives": []
        }

        patterns = self.patterns.get(vuln_type, [])
        for pattern in patterns:
            if re.search(pattern.regex, response_text):
                results["evidence"].append({
                    "pattern": pattern.regex,
                    "description": pattern.description,
                    "severity": pattern.severity
                })
                
                if pattern.false_positive_rate > 0.3:  # High false positive threshold
                    results["false_positives"].append(
                        f"Pattern '{pattern.description}' has high false positive rate"
                    )

        return results

    def _analyze_payload_reflection(
        self, response_text: str, payload: str, vuln_type: VulnerabilityType
    ) -> Dict:
        """Analyze how the payload is reflected in the response"""
        results = {"evidence": []}

        # Check for exact payload reflection
        if payload in response_text:
            results["evidence"].append({
                "type": "reflection",
                "description": "Exact payload reflection found",
                "severity": "high"
            })

        # Check for encoded versions
        encoded_checks = [
            (payload.encode('base64').decode(), "base64"),
            (payload.encode('hex').decode(), "hex"),
            # Add more encoding checks
        ]

        for encoded, encoding in encoded_checks:
            if encoded in response_text:
                results["evidence"].append({
                    "type": "reflection",
                    "description": f"Found {encoding} encoded payload reflection",
                    "severity": "medium"
                })

        return results

    def _context_based_detection(
        self, response_text: str, context: Dict, vuln_type: VulnerabilityType
    ) -> Dict:
        """Detect vulnerability based on request/response context"""
        results = {"evidence": []}

        # Check response code patterns
        if context.get("response_code"):
            if context["response_code"] >= 500:
                results["evidence"].append({
                    "type": "context",
                    "description": "Server error indicates potential vulnerability",
                    "severity": "medium"
                })

        # Check content type anomalies
        if context.get("content_type"):
            expected_types = {
                VulnerabilityType.XSS: ["text/html", "application/javascript"],
                VulnerabilityType.SQLI: ["text/html", "application/json"],
                # Add more mappings
            }
            if context["content_type"] not in expected_types.get(vuln_type, []):
                results["evidence"].append({
                    "type": "context",
                    "description": "Unexpected content type for vulnerability",
                    "severity": "low"
                })

        return results

    def _llm_based_detection(
        self, response_text: str, payload: str, vuln_type: VulnerabilityType
    ) -> Dict:
        """Use LLM to detect vulnerability"""
        try:
            query = f"""Analyze the following HTTP response for signs of {vuln_type.value} vulnerability exploitation.

Payload used:
{payload}

Response:
{response_text}

Consider:
1. Execution indicators
2. Error messages
3. Response anomalies
4. Potential false positives

Return JSON with fields: detected (boolean), confidence (0-1), reason (string)
"""
            result = generate_response(query)
            
            try:
                parsed = json.loads(result) if isinstance(result, str) else result
                return {
                    "detected": bool(parsed.get("detected", False)),
                    "confidence": float(parsed.get("confidence", 0.0)),
                    "reason": str(parsed.get("reason", "No reason provided"))
                }
            except (json.JSONDecodeError, ValueError):
                return {
                    "detected": False,
                    "confidence": 0.0,
                    "reason": "Failed to parse LLM response"
                }
                
        except Exception as e:
            logger.error(f"LLM detection error: {str(e)}")
            return {
                "detected": False,
                "confidence": 0.0,
                "reason": f"LLM detection failed: {str(e)}"
            }

    def _calculate_confidence(self, pattern_results: Dict, reflection_results: Dict,
                            context_results: Optional[Dict], llm_results: Dict) -> float:
        """Calculate overall confidence score"""
        confidence_factors = []

        # Pattern-based confidence
        if pattern_results["evidence"]:
            confidence_factors.append(len(pattern_results["evidence"]) * 0.3)

        # Reflection confidence
        if reflection_results["evidence"]:
            confidence_factors.append(len(reflection_results["evidence"]) * 0.2)

        # Context-based confidence
        if context_results and context_results["evidence"]:
            confidence_factors.append(len(context_results["evidence"]) * 0.2)

        # LLM confidence
        if llm_results["detected"]:
            confidence_factors.append(llm_results["confidence"] * 0.3)

        # Calculate final confidence
        return min(1.0, sum(confidence_factors))

    def _determine_severity(self, evidence: List[Dict]) -> str:
        """Determine overall severity based on evidence"""
        severity_scores = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }

        max_severity = 0
        for item in evidence:
            if isinstance(item, dict) and "severity" in item:
                score = severity_scores.get(item["severity"].lower(), 0)
                max_severity = max(max_severity, score)

        for severity, score in severity_scores.items():
            if score == max_severity:
                return severity

        return "low"

    def _generate_analysis(self, results: Dict) -> List[str]:
        """Generate detailed analysis summary"""
        analysis = []

        if results["detected"]:
            analysis.append(f"Vulnerability detected with {results['confidence']:.2f} confidence")
            analysis.append(f"Severity level: {results['severity'].upper()}")

            if results["evidence"]:
                analysis.append("\nEvidence found:")
                for item in results["evidence"]:
                    if isinstance(item, dict):
                        analysis.append(f"- {item.get('description', 'Unknown evidence')}")
                    else:
                        analysis.append(f"- {item}")

            if results["false_positives"]:
                analysis.append("\nPotential false positives:")
                for fp in results["false_positives"]:
                    analysis.append(f"- {fp}")
        else:
            analysis.append("No vulnerability detected")
            if results["evidence"]:
                analysis.append("Some indicators found but confidence threshold not met")

        return analysis

def get_detection_patterns() -> Dict[str, List[Dict]]:
    """Get all detection patterns"""
    detector = VulnerabilityDetector()
    return {
        vuln_type: [
            {
                "regex": pattern.regex,
                "description": pattern.description,
                "severity": pattern.severity,
                "false_positive_rate": pattern.false_positive_rate
            }
            for pattern in patterns
        ]
        for vuln_type, patterns in detector.patterns.items()
    }

def detect_vulnerability_llm(response_text: str, payload: str, vuln_type: str) -> Dict:
    """Legacy wrapper for backward compatibility"""
    detector = VulnerabilityDetector()
    return detector.detect_vulnerability(response_text, payload, vuln_type)
