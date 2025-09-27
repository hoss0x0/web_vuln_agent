"""Advanced WAF detection and strategy adaptation system."""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

from utils.logger import setup_logger

logger = setup_logger(__name__)

class WAFVendor(Enum):
    """Known WAF vendors and products"""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5 = "f5"
    FORTINET = "fortinet"
    AWS = "aws_waf"
    NGINX = "nginx"
    MODSECURITY = "modsecurity"
    UNKNOWN = "unknown"

class DetectionType(Enum):
    """Types of WAF detection methods"""
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    RATE_LIMIT = "rate_limit"
    REPUTATION = "reputation"
    ML_BASED = "ml_based"
    UNKNOWN = "unknown"

class AdaptationStrategy(Enum):
    """WAF evasion strategies"""
    ENCODING = "encoding"
    FRAGMENTATION = "fragmentation"
    OBFUSCATION = "obfuscation"
    POLYMORPHIC = "polymorphic"
    TIME_BASED = "time_based"
    HEADERS_BASED = "headers_based"
    SESSION_BASED = "session_based"
    DISTRIBUTED = "distributed"

@dataclass
class WAFProfile:
    """Profile of detected WAF behavior"""
    vendor: WAFVendor
    detection_types: Set[DetectionType]
    sensitivity: float  # 0.0 to 1.0
    block_patterns: List[str]
    bypass_history: List[Tuple[AdaptationStrategy, bool]]
    last_updated: datetime

@dataclass
class ResponseAnalysis:
    """Analysis of WAF response"""
    is_blocked: bool
    detection_type: DetectionType
    confidence: float
    extracted_patterns: List[str]
    response_time: float
    status_code: int

@dataclass
class StrategyResult:
    """Result of strategy adaptation"""
    strategy: AdaptationStrategy
    confidence: float
    estimated_success: float
    fallback_strategies: List[AdaptationStrategy]
    context: Dict[str, str]

class WAFStrategyAdapter:
    """Advanced WAF strategy adaptation system"""
    
    def __init__(self):
        self._initialize_patterns()
        self.waf_profiles: Dict[str, WAFProfile] = {}
        self.detection_history: List[Tuple[datetime, ResponseAnalysis]] = []
        
    def _initialize_patterns(self) -> None:
        """Initialize WAF detection patterns"""
        self.patterns = {
            WAFVendor.CLOUDFLARE: {
                "headers": ["cf-ray", "cf-cache-status"],
                "bodies": [
                    r"cloudflare ray id",
                    r"attention required!.*security check"
                ],
                "detection_types": {DetectionType.SIGNATURE, DetectionType.RATE_LIMIT}
            },
            WAFVendor.AKAMAI: {
                "headers": ["akamai-", "x-akamai-"],
                "bodies": [r"access denied.*reference \#[0-9a-f]{8}"],
                "detection_types": {DetectionType.BEHAVIORAL, DetectionType.REPUTATION}
            },
            # Add more vendor patterns
        }
        
    def analyze_response(self, response_text: str,
                        headers: Dict[str, str],
                        status_code: int,
                        response_time: float) -> ResponseAnalysis:
        """Analyze WAF response characteristics"""
        try:
            is_blocked = self._check_if_blocked(response_text, status_code)
            detection_type = self._identify_detection_type(response_text, headers)
            confidence = self._calculate_confidence(response_text, headers)
            patterns = self._extract_patterns(response_text, headers)
            
            return ResponseAnalysis(
                is_blocked=is_blocked,
                detection_type=detection_type,
                confidence=confidence,
                extracted_patterns=patterns,
                response_time=response_time,
                status_code=status_code
            )
        except Exception as e:
            logger.error(f"Response analysis failed: {str(e)}")
            return ResponseAnalysis(
                is_blocked=True,
                detection_type=DetectionType.UNKNOWN,
                confidence=0.5,
                extracted_patterns=[],
                response_time=response_time,
                status_code=status_code
            )

    def adapt_strategy(self, vuln_type: str,
                      response_text: str,
                      headers: Optional[Dict[str, str]] = None,
                      context: Optional[Dict[str, str]] = None) -> StrategyResult:
        """
        Adapt WAF evasion strategy based on response analysis
        
        Args:
            vuln_type: Type of vulnerability being tested
            response_text: WAF response content
            headers: Optional response headers
            context: Optional additional context
            
        Returns:
            StrategyResult with adapted strategy and metadata
        """
        try:
            headers = headers or {}
            context = context or {}
            
            # Analyze response
            analysis = self.analyze_response(
                response_text,
                headers,
                status_code=int(context.get("status_code", 403)),
                response_time=float(context.get("response_time", 0.0))
            )
            
            # Update WAF profile
            self._update_waf_profile(analysis, vuln_type)
            
            # Select primary strategy
            strategy = self._select_strategy(analysis, vuln_type)
            
            # Calculate confidence and success probability
            confidence = self._calculate_strategy_confidence(strategy, analysis)
            success_prob = self._estimate_success_probability(strategy, analysis)
            
            # Select fallback strategies
            fallbacks = self._select_fallback_strategies(strategy, analysis)
            
            # Record the detection
            self.detection_history.append((datetime.utcnow(), analysis))
            
            # Trim history if needed
            if len(self.detection_history) > 1000:
                self.detection_history = self.detection_history[-1000:]
            
            return StrategyResult(
                strategy=strategy,
                confidence=confidence,
                estimated_success=success_prob,
                fallback_strategies=fallbacks,
                context={
                    "detection_type": analysis.detection_type.value,
                    "is_blocked": str(analysis.is_blocked),
                    "confidence": f"{confidence:.2f}",
                    "patterns": json.dumps(analysis.extracted_patterns)
                }
            )
            
        except Exception as e:
            logger.error(f"Strategy adaptation failed: {str(e)}")
            # Return conservative default strategy
            return StrategyResult(
                strategy=AdaptationStrategy.OBFUSCATION,
                confidence=0.5,
                estimated_success=0.3,
                fallback_strategies=[
                    AdaptationStrategy.ENCODING,
                    AdaptationStrategy.TIME_BASED
                ],
                context={"error": str(e)}
            )

    def _check_if_blocked(self, response_text: str, status_code: int) -> bool:
        """Check if request was blocked by WAF"""
        block_indicators = {
            "status_codes": {403, 406, 429, 456},
            "keywords": [
                "blocked", "forbidden", "access denied", "security check",
                "suspicious", "malicious", "violation", "attack", "waf"
            ]
        }
        
        if status_code in block_indicators["status_codes"]:
            return True
            
        return any(kw.lower() in response_text.lower() 
                  for kw in block_indicators["keywords"])

    def _identify_detection_type(self, response_text: str,
                               headers: Dict[str, str]) -> DetectionType:
        """Identify WAF detection method used"""
        indicators = {
            DetectionType.SIGNATURE: [
                r"attack signature|attack pattern|rule id|security rule",
                r"(?:sql|xss|rfi|lfi) attack detected"
            ],
            DetectionType.BEHAVIORAL: [
                r"abnormal|suspicious|unusual|behavior|pattern",
                r"automated|bot|crawler|spider"
            ],
            DetectionType.RATE_LIMIT: [
                r"too many requests|rate limit|frequency|throttle",
                r"wait \d+ seconds|try again later"
            ],
            DetectionType.REPUTATION: [
                r"ip.+blacklisted|banned|blocked",
                r"reputation|trust score|risk score"
            ],
            DetectionType.ML_BASED: [
                r"machine learning|ai detection|automated analysis",
                r"behavioral analysis|anomaly detection"
            ]
        }
        
        # Check response and headers against indicators
        for dtype, patterns in indicators.items():
            if any(re.search(p, response_text, re.I) for p in patterns):
                return dtype
            if any(re.search(p, str(headers), re.I) for p in patterns):
                return dtype
                
        return DetectionType.UNKNOWN

    def _calculate_confidence(self, response_text: str,
                            headers: Dict[str, str]) -> float:
        """Calculate confidence in WAF detection"""
        confidence = 0.0
        indicators_found = 0
        
        # Check status code
        status = headers.get("status", "").split()[0]
        if status in {"403", "406", "429", "456"}:
            confidence += 0.3
            indicators_found += 1
            
        # Check WAF-specific headers
        waf_headers = {
            "x-firewall-", "x-waf-", "x-security-",
            "cf-", "akamai-", "x-cdn-"
        }
        for header in headers:
            if any(h in header.lower() for h in waf_headers):
                confidence += 0.2
                indicators_found += 1
                
        # Check response patterns
        patterns = [
            r"(?i)blocked|forbidden|denied|suspicious",
            r"(?i)waf|firewall|security|protection",
            r"(?i)attack|threat|violation|malicious"
        ]
        for pattern in patterns:
            if re.search(pattern, response_text):
                confidence += 0.15
                indicators_found += 1
                
        if indicators_found > 0:
            confidence = min(confidence, 1.0)
        
        return confidence

    def _extract_patterns(self, response_text: str,
                         headers: Dict[str, str]) -> List[str]:
        """Extract WAF fingerprints and patterns"""
        patterns = []
        
        # Extract from headers
        for header, value in headers.items():
            if any(v in header.lower() for v in ["waf", "security", "firewall"]):
                patterns.append(f"header:{header}={value}")
                
        # Extract from response body
        body_patterns = [
            r"rule id: (\d+)",
            r"reference #([0-9a-f]+)",
            r"block id: ([0-9a-f-]+)",
            r"incident: ([0-9a-f]+)"
        ]
        
        for pattern in body_patterns:
            matches = re.finditer(pattern, response_text, re.I)
            patterns.extend(f"body:{m.group(1)}" for m in matches)
            
        return patterns

    def _update_waf_profile(self, analysis: ResponseAnalysis,
                           vuln_type: str) -> None:
        """Update WAF behavior profile"""
        try:
            if not hasattr(self, "current_profile"):
                self.current_profile = WAFProfile(
                    vendor=WAFVendor.UNKNOWN,
                    detection_types=set(),
                    sensitivity=0.5,
                    block_patterns=[],
                    bypass_history=[],
                    last_updated=datetime.utcnow()
                )
            
            # Update detection types
            self.current_profile.detection_types.add(analysis.detection_type)
            
            # Update block patterns
            self.current_profile.block_patterns.extend(analysis.extracted_patterns)
            
            # Update sensitivity based on analysis
            if analysis.is_blocked:
                self.current_profile.sensitivity = min(
                    1.0,
                    self.current_profile.sensitivity + 0.1
                )
            else:
                self.current_profile.sensitivity = max(
                    0.0,
                    self.current_profile.sensitivity - 0.05
                )
                
            self.current_profile.last_updated = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Failed to update WAF profile: {str(e)}")

    def _select_strategy(self, analysis: ResponseAnalysis,
                        vuln_type: str) -> AdaptationStrategy:
        """Select best evasion strategy based on analysis"""
        try:
            if analysis.detection_type == DetectionType.SIGNATURE:
                return AdaptationStrategy.POLYMORPHIC
            elif analysis.detection_type == DetectionType.BEHAVIORAL:
                return AdaptationStrategy.TIME_BASED
            elif analysis.detection_type == DetectionType.RATE_LIMIT:
                return AdaptationStrategy.DISTRIBUTED
            elif analysis.detection_type == DetectionType.ML_BASED:
                return AdaptationStrategy.FRAGMENTATION
            elif analysis.detection_type == DetectionType.REPUTATION:
                return AdaptationStrategy.SESSION_BASED
            else:
                return AdaptationStrategy.OBFUSCATION
                
        except Exception as e:
            logger.error(f"Strategy selection failed: {str(e)}")
            return AdaptationStrategy.OBFUSCATION

    def _calculate_strategy_confidence(self, strategy: AdaptationStrategy,
                                    analysis: ResponseAnalysis) -> float:
        """Calculate confidence in selected strategy"""
        try:
            # Base confidence from analysis
            confidence = analysis.confidence
            
            # Adjust based on detection type match
            detection_strategy_map = {
                DetectionType.SIGNATURE: {
                    AdaptationStrategy.POLYMORPHIC: 0.3,
                    AdaptationStrategy.OBFUSCATION: 0.2
                },
                DetectionType.BEHAVIORAL: {
                    AdaptationStrategy.TIME_BASED: 0.3,
                    AdaptationStrategy.SESSION_BASED: 0.2
                },
                DetectionType.RATE_LIMIT: {
                    AdaptationStrategy.DISTRIBUTED: 0.3,
                    AdaptationStrategy.TIME_BASED: 0.2
                }
            }
            
            confidence += detection_strategy_map.get(analysis.detection_type, {}).get(strategy, 0.0)
            
            # Adjust based on historical success
            if hasattr(self, "current_profile"):
                success_rate = self._get_strategy_success_rate(strategy)
                confidence += success_rate * 0.2
                
            return min(1.0, max(0.0, confidence))
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {str(e)}")
            return 0.5

    def _estimate_success_probability(self, strategy: AdaptationStrategy,
                                   analysis: ResponseAnalysis) -> float:
        """Estimate probability of strategy success"""
        try:
            # Base probability from confidence
            prob = self._calculate_strategy_confidence(strategy, analysis)
            
            # Adjust based on WAF sensitivity
            if hasattr(self, "current_profile"):
                sensitivity = self.current_profile.sensitivity
                prob *= (1 - sensitivity)
                
            # Adjust based on vulnerability type effectiveness
            vuln_effectiveness = {
                "sqli": 0.8,
                "xss": 0.7,
                "rce": 0.6,
                "lfi": 0.7,
                "rfi": 0.6
            }
            prob *= vuln_effectiveness.get("sqli", 0.5)  # Default if unknown
            
            return min(1.0, max(0.0, prob))
            
        except Exception as e:
            logger.error(f"Success probability calculation failed: {str(e)}")
            return 0.3

    def _select_fallback_strategies(self, primary: AdaptationStrategy,
                                  analysis: ResponseAnalysis
                                  ) -> List[AdaptationStrategy]:
        """Select alternative strategies if primary fails"""
        try:
            # All strategies except primary
            available = [s for s in AdaptationStrategy if s != primary]
            
            # Score each strategy
            scored_strategies = []
            for strategy in available:
                score = self._calculate_strategy_confidence(strategy, analysis)
                scored_strategies.append((score, strategy))
                
            # Sort by score and take top 2
            scored_strategies.sort(reverse=True)
            return [s[1] for s in scored_strategies[:2]]
            
        except Exception as e:
            logger.error(f"Fallback selection failed: {str(e)}")
            return [
                AdaptationStrategy.ENCODING,
                AdaptationStrategy.OBFUSCATION
            ]

    def _get_strategy_success_rate(self, strategy: AdaptationStrategy) -> float:
        """Calculate historical success rate for strategy"""
        try:
            if not hasattr(self, "current_profile"):
                return 0.5
                
            relevant_history = [
                success for strat, success in self.current_profile.bypass_history
                if strat == strategy
            ]
            
            if not relevant_history:
                return 0.5
                
            return sum(relevant_history) / len(relevant_history)
            
        except Exception as e:
            logger.error(f"Success rate calculation failed: {str(e)}")
            return 0.5
