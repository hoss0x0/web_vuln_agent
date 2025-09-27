import json
import re
import logging
from typing import Dict, List, Union, Optional
from dataclasses import dataclass
from enum import Enum
from rag_layer.rag_chain import generate_response
from chains.analysis.detection_heuristics import get_detection_patterns
from chains.analysis.response_diff import calculate_response_similarity
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Supported vulnerability types for confidence scoring"""
    XSS = "xss"
    SQLI = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"

@dataclass
class ConfidenceMetrics:
    """Detailed metrics for confidence scoring"""
    pattern_match_score: float = 0.0
    response_diff_score: float = 0.0
    error_pattern_score: float = 0.0
    payload_reflection_score: float = 0.0
    context_analysis_score: float = 0.0
    llm_confidence_score: float = 0.0

class ConfidenceScorer:
    """Enhanced confidence scoring system for vulnerability validation"""
    
    def __init__(self):
        self.detection_patterns = get_detection_patterns()
        self.min_confidence_threshold = 0.6
        self.weights = {
            "pattern_match": 0.3,
            "response_diff": 0.2,
            "error_patterns": 0.15,
            "payload_reflection": 0.2,
            "context_analysis": 0.1,
            "llm_confidence": 0.05
        }

    def score_confidence(
        self,
        response_text: str,
        payload: str,
        vuln_type: Union[str, VulnerabilityType],
        original_response: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Calculate confidence score for vulnerability exploitation
        
        Args:
            response_text: The response text to analyze
            payload: The payload that was used
            vuln_type: Type of vulnerability being tested
            original_response: Original response for comparison (optional)
            context: Additional context about the request/response (optional)
            
        Returns:
            Dictionary containing confidence score and detailed analysis
        """
        try:
            # Convert string vuln_type to enum if needed
            if isinstance(vuln_type, str):
                vuln_type = VulnerabilityType(vuln_type.lower())

            # Initialize metrics
            metrics = ConfidenceMetrics()

            # Pattern matching score
            metrics.pattern_match_score = self._calculate_pattern_match_score(
                response_text, payload, vuln_type
            )

            # Response difference score
            if original_response:
                metrics.response_diff_score = self._calculate_response_diff_score(
                    original_response, response_text
                )

            # Error pattern analysis
            metrics.error_pattern_score = self._analyze_error_patterns(
                response_text, vuln_type
            )

            # Payload reflection analysis
            metrics.payload_reflection_score = self._analyze_payload_reflection(
                response_text, payload, vuln_type
            )

            # Context-based analysis
            if context:
                metrics.context_analysis_score = self._analyze_context(
                    response_text, context, vuln_type
                )

            # LLM-based confidence scoring
            metrics.llm_confidence_score = self._get_llm_confidence_score(
                response_text, payload, vuln_type
            )

            # Calculate final weighted score
            final_score = self._calculate_final_score(metrics)

            # Generate detailed analysis
            analysis = self._generate_analysis_report(metrics, final_score, vuln_type)

            return {
                "score": final_score,
                "confidence_level": self._get_confidence_level(final_score),
                "metrics": self._metrics_to_dict(metrics),
                "analysis": analysis,
                "is_confident": final_score >= self.min_confidence_threshold
            }

        except Exception as e:
            logger.error(f"Error in confidence scoring: {str(e)}")
            return {
                "score": 0.0,
                "confidence_level": "error",
                "metrics": {},
                "analysis": f"Error during analysis: {str(e)}",
                "is_confident": False
            }

    def _calculate_pattern_match_score(
        self, response_text: str, payload: str, vuln_type: VulnerabilityType
    ) -> float:
        """Calculate score based on known vulnerability patterns"""
        try:
            patterns = self.detection_patterns.get(vuln_type.value, [])
            matches = 0
            
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matches += 1
                    
            return matches / len(patterns) if patterns else 0.0
            
        except Exception as e:
            logger.error(f"Pattern matching error: {str(e)}")
            return 0.0

    def _calculate_response_diff_score(
        self, original_response: str, current_response: str
    ) -> float:
        """Calculate similarity score between original and current response"""
        try:
            return 1.0 - calculate_response_similarity(original_response, current_response)
        except Exception as e:
            logger.error(f"Response diff error: {str(e)}")
            return 0.0

    def _analyze_error_patterns(
        self, response_text: str, vuln_type: VulnerabilityType
    ) -> float:
        """Analyze response for error patterns indicating successful exploitation"""
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
            # Add patterns for other vulnerability types
        }
        
        try:
            patterns = error_patterns.get(vuln_type, [])
            matches = 0
            
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matches += 1
                    
            return matches / len(patterns) if patterns else 0.0
            
        except Exception as e:
            logger.error(f"Error pattern analysis error: {str(e)}")
            return 0.0

    def _analyze_payload_reflection(
        self, response_text: str, payload: str, vuln_type: VulnerabilityType
    ) -> float:
        """Analyze how the payload is reflected in the response"""
        try:
            # Check for exact payload reflection
            exact_reflection = payload in response_text
            
            # Check for encoded versions
            encoded_reflections = [
                payload.encode('base64').decode(),
                payload.encode('hex').decode(),
                # Add more encoding checks
            ]
            
            # Check for partial matches
            payload_parts = payload.split()
            partial_matches = sum(1 for part in payload_parts if part in response_text)
            
            # Calculate weighted score
            score = (
                (1.0 if exact_reflection else 0.0) * 0.6 +
                (sum(1 for e in encoded_reflections if e in response_text) / len(encoded_reflections)) * 0.2 +
                (partial_matches / len(payload_parts) if payload_parts else 0.0) * 0.2
            )
            
            return score
            
        except Exception as e:
            logger.error(f"Payload reflection analysis error: {str(e)}")
            return 0.0

    def _analyze_context(
        self, response_text: str, context: Dict, vuln_type: VulnerabilityType
    ) -> float:
        """Analyze response in the context of the request and vulnerability type"""
        try:
            score_factors = []
            
            # Check response code
            if context.get("response_code"):
                if context["response_code"] in [200, 301, 302]:
                    score_factors.append(0.8)
                elif context["response_code"] >= 500:
                    score_factors.append(0.4)  # Server errors might indicate successful injection
                    
            # Check content type
            if context.get("content_type"):
                expected_types = {
                    VulnerabilityType.XSS: ["text/html", "application/javascript"],
                    VulnerabilityType.SQLI: ["text/html", "application/json"],
                    # Add more type mappings
                }
                if context["content_type"] in expected_types.get(vuln_type, []):
                    score_factors.append(0.7)
                    
            # Check response size
            if context.get("original_size") and context.get("current_size"):
                size_diff = abs(context["current_size"] - context["original_size"])
                if size_diff > 100:  # Significant change
                    score_factors.append(0.6)
                    
            return sum(score_factors) / len(score_factors) if score_factors else 0.0
            
        except Exception as e:
            logger.error(f"Context analysis error: {str(e)}")
            return 0.0

    def _get_llm_confidence_score(
        self, response_text: str, payload: str, vuln_type: VulnerabilityType
    ) -> float:
        """Get confidence score from LLM analysis"""
        try:
            query = f"""Analyze the following HTTP response for signs of successful {vuln_type.value} exploitation.

Payload used:
{payload}

Response:
{response_text}

Provide:
1. Confidence score (0-1)
2. Key indicators found
3. Potential false positive factors

Return as JSON with fields: score, indicators, false_positives
"""
            result = generate_response(query)
            
            try:
                parsed = json.loads(result) if isinstance(result, str) else result
                return float(parsed.get("score", 0.0))
            except (json.JSONDecodeError, ValueError):
                return 0.0
                
        except Exception as e:
            logger.error(f"LLM confidence scoring error: {str(e)}")
            return 0.0

    def _calculate_final_score(self, metrics: ConfidenceMetrics) -> float:
        """Calculate final weighted confidence score"""
        try:
            weighted_scores = [
                metrics.pattern_match_score * self.weights["pattern_match"],
                metrics.response_diff_score * self.weights["response_diff"],
                metrics.error_pattern_score * self.weights["error_patterns"],
                metrics.payload_reflection_score * self.weights["payload_reflection"],
                metrics.context_analysis_score * self.weights["context_analysis"],
                metrics.llm_confidence_score * self.weights["llm_confidence"]
            ]
            
            return sum(weighted_scores)
            
        except Exception as e:
            logger.error(f"Final score calculation error: {str(e)}")
            return 0.0

    def _get_confidence_level(self, score: float) -> str:
        """Convert numerical score to confidence level string"""
        if score >= 0.8:
            return "high"
        elif score >= 0.6:
            return "medium"
        elif score >= 0.3:
            return "low"
        else:
            return "insufficient"

    def _metrics_to_dict(self, metrics: ConfidenceMetrics) -> Dict:
        """Convert metrics to dictionary for JSON serialization"""
        return {
            "pattern_match_score": metrics.pattern_match_score,
            "response_diff_score": metrics.response_diff_score,
            "error_pattern_score": metrics.error_pattern_score,
            "payload_reflection_score": metrics.payload_reflection_score,
            "context_analysis_score": metrics.context_analysis_score,
            "llm_confidence_score": metrics.llm_confidence_score
        }

    def _generate_analysis_report(
        self, metrics: ConfidenceMetrics, final_score: float, vuln_type: VulnerabilityType
    ) -> str:
        """Generate detailed analysis report"""
        try:
            reports = []
            
            if metrics.pattern_match_score > 0:
                reports.append(f"Found {vuln_type.value} signature patterns")
                
            if metrics.response_diff_score > 0.5:
                reports.append("Significant response differences detected")
                
            if metrics.error_pattern_score > 0:
                reports.append("Detected error patterns indicating successful exploitation")
                
            if metrics.payload_reflection_score > 0.7:
                reports.append("High payload reflection detected")
                
            if metrics.context_analysis_score > 0.5:
                reports.append("Context analysis indicates successful exploitation")
                
            confidence_level = self._get_confidence_level(final_score)
            
            return f"Confidence Level: {confidence_level.upper()}\n" + "\n".join(f"- {r}" for r in reports)
            
        except Exception as e:
            logger.error(f"Analysis report generation error: {str(e)}")
            return "Error generating analysis report"

def score_confidence_llm(response_text: str, payload: str) -> Dict:
    """Legacy wrapper for backward compatibility"""
    scorer = ConfidenceScorer()
    return scorer.score_confidence(response_text, payload, VulnerabilityType.XSS)
