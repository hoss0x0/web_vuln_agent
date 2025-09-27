"""Advanced WAF detection system using hybrid approach (LLM + Pattern Matching)."""

import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger

logger = setup_logger(__name__)

class WAFVendor(Enum):
    """Known WAF vendors and products"""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5_ASM = "f5_asm"
    FORTINET = "fortinet"
    AWS_WAF = "aws_waf"
    NGINX_APP_PROTECT = "nginx_app_protect"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    UNKNOWN = "unknown"

@dataclass
class WAFSignature:
    """WAF signature patterns"""
    vendor: WAFVendor
    headers: List[str]
    header_patterns: List[str]
    body_patterns: List[str]
    response_codes: Set[int]
    confidence_weight: float

@dataclass
class WAFResponse:
    """WAF detection response details"""
    detected: bool
    vendor: WAFVendor
    confidence: float
    signatures_matched: List[str]
    response_characteristics: Dict[str, str]
    llm_analysis: Dict[str, str]
    timestamp: datetime
    response_hash: str

class WAFDetector:
    """Advanced WAF Detection System"""
    
    def __init__(self):
        self._initialize_signatures()
        self.detection_history: List[WAFResponse] = []
        self.max_history = 1000
        
    def _initialize_signatures(self) -> None:
        """Initialize WAF detection signatures"""
        self.signatures: Dict[WAFVendor, WAFSignature] = {
            WAFVendor.CLOUDFLARE: WAFSignature(
                vendor=WAFVendor.CLOUDFLARE,
                headers=[
                    "cf-ray",
                    "cf-cache-status",
                    "__cfduid",
                    "cf-request-id"
                ],
                header_patterns=[
                    r"^cf-[a-zA-Z0-9-]+$",
                    r"cloudflare-nginx"
                ],
                body_patterns=[
                    r"cloudflare ray id: [a-f0-9]{16}",
                    r"attention required!.*security check",
                    r"sorry, you have been blocked",
                    r"please turn javascript on and reload the page"
                ],
                response_codes={403, 429, 503},
                confidence_weight=0.9
            ),
            WAFVendor.AKAMAI: WAFSignature(
                vendor=WAFVendor.AKAMAI,
                headers=[
                    "x-akamai-transformed",
                    "akamai-x-cache-on",
                    "akamai-x-get-cache-key"
                ],
                header_patterns=[
                    r"akamai",
                    r"aka(mai)?-"
                ],
                body_patterns=[
                    r"access denied.*reference #[0-9a-f]{8}",
                    r"your request has been blocked",
                    r"the requested url was rejected"
                ],
                response_codes={403, 406, 503},
                confidence_weight=0.85
            ),
            # Add more vendor signatures
        }
        
    def detect_waf(self,
                   response_text: str,
                   headers: Optional[Dict[str, str]] = None,
                   status_code: Optional[int] = None) -> WAFResponse:
        """
        Detect WAF presence using hybrid approach (pattern matching + LLM)
        
        Args:
            response_text: The response body text
            headers: Optional response headers dictionary
            status_code: Optional HTTP status code
            
        Returns:
            WAFResponse with detection details
        """
        try:
            headers = headers or {}
            status_code = status_code or 200
            
            # Generate response hash for tracking
            response_hash = self._generate_response_hash(response_text, headers)
            
            # Pattern-based detection
            pattern_results = self._detect_patterns(
                response_text,
                headers,
                status_code
            )
            
            # LLM-based detection
            llm_results = self._detect_with_llm(
                response_text,
                headers,
                status_code
            )
            
            # Combine results
            combined_results = self._combine_detection_results(
                pattern_results,
                llm_results
            )
            
            # Create response
            response = WAFResponse(
                detected=combined_results["detected"],
                vendor=combined_results["vendor"],
                confidence=combined_results["confidence"],
                signatures_matched=combined_results["signatures"],
                response_characteristics=combined_results["characteristics"],
                llm_analysis=llm_results,
                timestamp=datetime.utcnow(),
                response_hash=response_hash
            )
            
            # Record detection
            self._record_detection(response)
            
            # Log findings
            if response.detected:
                logger.warning(
                    f"WAF detected: {response.vendor.value} "
                    f"(confidence: {response.confidence:.2f})"
                )
                for sig in response.signatures_matched[:3]:
                    logger.info(f"Matched signature: {sig}")
            
            return response
            
        except Exception as e:
            logger.error(f"WAF detection failed: {str(e)}")
            return WAFResponse(
                detected=False,
                vendor=WAFVendor.UNKNOWN,
                confidence=0.0,
                signatures_matched=[],
                response_characteristics={},
                llm_analysis={"error": str(e)},
                timestamp=datetime.utcnow(),
                response_hash=self._generate_response_hash(response_text, headers)
            )
            
    def _detect_patterns(self,
                        response_text: str,
                        headers: Dict[str, str],
                        status_code: int
                        ) -> Dict[str, any]:
        """Pattern-based WAF detection"""
        results = {
            "detected": False,
            "vendors": set(),
            "signatures": [],
            "confidence": 0.0
        }
        
        # Check each vendor's signatures
        for vendor, signature in self.signatures.items():
            vendor_confidence = 0.0
            matches = []
            
            # Check headers presence
            for header in signature.headers:
                if header.lower() in [h.lower() for h in headers]:
                    vendor_confidence += 0.3
                    matches.append(f"header:{header}")
                    
            # Check header patterns
            for pattern in signature.header_patterns:
                for header, value in headers.items():
                    if re.search(pattern, header, re.I) or \
                       re.search(pattern, value, re.I):
                        vendor_confidence += 0.2
                        matches.append(f"header_pattern:{pattern}")
                        
            # Check body patterns
            for pattern in signature.body_patterns:
                if re.search(pattern, response_text, re.I):
                    vendor_confidence += 0.25
                    matches.append(f"body_pattern:{pattern}")
                    
            # Check status code
            if status_code in signature.response_codes:
                vendor_confidence += 0.15
                matches.append(f"status_code:{status_code}")
                
            # Apply vendor weight
            vendor_confidence *= signature.confidence_weight
            
            if vendor_confidence > 0:
                results["vendors"].add(vendor)
                results["signatures"].extend(
                    f"{vendor.value}:{match}" for match in matches
                )
                results["confidence"] = max(
                    results["confidence"],
                    vendor_confidence
                )
                
        results["detected"] = len(results["vendors"]) > 0
        return results
        
    def _detect_with_llm(self,
                        response_text: str,
                        headers: Dict[str, str],
                        status_code: int
                        ) -> Dict[str, any]:
        """LLM-based WAF detection"""
        query = f"""Analyze this HTTP response for WAF (Web Application Firewall) presence.
Consider headers, response code, and body content.

Status Code: {status_code}

Headers:
{json.dumps(headers, indent=2)}

Response Body:
{response_text[:1000]}  # Truncate for LLM

Analyze for:
1. WAF presence indicators
2. Specific WAF vendor signs
3. Confidence level (0.0-1.0)
4. Key characteristics suggesting WAF

Return a JSON object with:
{{
    "detected": bool,
    "vendor": string,
    "confidence": float,
    "characteristics": list[string],
    "reasoning": string
}}
"""
        try:
            result = generate_response(query)
            return json.loads(result)
        except Exception as e:
            logger.error(f"LLM detection failed: {str(e)}")
            return {
                "detected": False,
                "vendor": "unknown",
                "confidence": 0.0,
                "characteristics": [],
                "reasoning": f"LLM analysis failed: {str(e)}"
            }
            
    def _combine_detection_results(self,
                                 pattern_results: Dict[str, any],
                                 llm_results: Dict[str, any]
                                 ) -> Dict[str, any]:
        """Combine pattern matching and LLM results"""
        combined = {
            "detected": False,
            "vendor": WAFVendor.UNKNOWN,
            "confidence": 0.0,
            "signatures": [],
            "characteristics": {}
        }
        
        # Weight the results (pattern:llm)
        pattern_weight = 0.6
        llm_weight = 0.4
        
        # Determine detection
        pattern_detected = pattern_results["detected"]
        llm_detected = llm_results.get("detected", False)
        
        if pattern_detected and llm_detected:
            combined["detected"] = True
            combined["confidence"] = (
                pattern_results["confidence"] * pattern_weight +
                llm_results.get("confidence", 0.0) * llm_weight
            )
        elif pattern_detected:
            combined["detected"] = True
            combined["confidence"] = pattern_results["confidence"] * 0.8
        elif llm_detected:
            combined["detected"] = True
            combined["confidence"] = llm_results.get("confidence", 0.0) * 0.6
            
        # Determine vendor
        if pattern_results["vendors"]:
            # Use the vendor with highest confidence from pattern matching
            combined["vendor"] = next(iter(pattern_results["vendors"]))
        elif llm_results.get("vendor"):
            try:
                combined["vendor"] = WAFVendor(llm_results["vendor"].lower())
            except ValueError:
                combined["vendor"] = WAFVendor.UNKNOWN
                
        # Combine signatures and characteristics
        combined["signatures"] = pattern_results["signatures"]
        combined["characteristics"] = {
            "pattern_matches": len(pattern_results["signatures"]),
            "llm_characteristics": llm_results.get("characteristics", []),
            "llm_reasoning": llm_results.get("reasoning", "")
        }
        
        return combined
        
    def _generate_response_hash(self,
                              response_text: str,
                              headers: Dict[str, str]) -> str:
        """Generate hash of response for tracking"""
        content = f"{json.dumps(headers)}|{response_text}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
        
    def _record_detection(self, response: WAFResponse) -> None:
        """Record detection for analysis"""
        try:
            self.detection_history.append(response)
            
            # Maintain history size
            if len(self.detection_history) > self.max_history:
                self.detection_history = self.detection_history[-self.max_history:]
                
        except Exception as e:
            logger.error(f"Failed to record detection: {str(e)}")
            
    def get_detection_stats(self) -> Dict[str, any]:
        """Get detection statistics"""
        try:
            stats = {
                "total_detections": len(self.detection_history),
                "detected_count": sum(
                    1 for r in self.detection_history if r.detected
                ),
                "vendor_distribution": {},
                "average_confidence": 0.0,
                "recent_detections": []
            }
            
            # Calculate vendor distribution
            for response in self.detection_history:
                if response.detected:
                    vendor = response.vendor.value
                    stats["vendor_distribution"][vendor] = \
                        stats["vendor_distribution"].get(vendor, 0) + 1
                        
            # Calculate average confidence
            if stats["detected_count"] > 0:
                stats["average_confidence"] = sum(
                    r.confidence for r in self.detection_history if r.detected
                ) / stats["detected_count"]
                
            # Get recent detections
            stats["recent_detections"] = [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "vendor": r.vendor.value,
                    "confidence": r.confidence,
                    "signatures": len(r.signatures_matched)
                }
                for r in self.detection_history[-5:]
                if r.detected
            ]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get detection stats: {str(e)}")
            return {}
