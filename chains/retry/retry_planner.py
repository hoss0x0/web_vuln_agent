"""Advanced retry planning and failure analysis system."""

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
from datetime import datetime, timedelta

from rag_layer.rag_chain import generate_response
from chains.retry.payload_evasion import PayloadEvasion, EvasionConfig
from chains.waf.waf_detector import WAFDetector
from utils.logger import setup_logger

logger = setup_logger(__name__)

class FailureReason(Enum):
    """Types of payload failure reasons"""
    WAF_BLOCK = "waf_block"
    RATE_LIMIT = "rate_limit"
    INPUT_VALIDATION = "input_validation"
    AUTH_FAILURE = "auth_failure"
    SYNTAX_ERROR = "syntax_error"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"

class RetryStrategy(Enum):
    """Types of retry strategies"""
    BACKOFF = "backoff"
    WAF_EVASION = "waf_evasion"
    PAYLOAD_MUTATION = "payload_mutation"
    TIMING_ADJUSTMENT = "timing_adjustment"
    AUTH_REFRESH = "auth_refresh"
    PROXY_ROTATION = "proxy_rotation"
    ERROR_CORRECTION = "error_correction"
    ALTERNATIVE_VECTOR = "alternative_vector"

@dataclass
class RetryConfig:
    """Configuration for retry attempts"""
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 30.0
    timeout: float = 60.0
    allowed_strategies: List[RetryStrategy] = field(default_factory=list)
    preserve_session: bool = True
    track_failures: bool = True

@dataclass
class FailurePattern:
    """Pattern for identifying failure reasons"""
    reason: FailureReason
    pattern: str
    confidence: float
    examples: List[str] = field(default_factory=list)
    detection_count: int = 0
    
@dataclass
class RetryAttempt:
    """Record of a retry attempt"""
    original_payload: str
    modified_payload: str
    strategy: RetryStrategy
    timestamp: datetime
    success: bool
    response: Optional[str] = None
    error: Optional[str] = None
    duration: float = 0.0

@dataclass
class RetryResult:
    """Result of retry planning"""
    failure_reason: FailureReason
    suggested_strategy: RetryStrategy
    modified_payload: str
    next_delay: float
    context: Dict[str, Any]
    confidence: float

class RetryPlanner:
    """Advanced retry planning system"""
    
    def __init__(self):
        self.payload_evasion = PayloadEvasion()
        self.waf_detector = WAFDetector()
        self.failure_patterns = self._initialize_patterns()
        self.attempt_history: Dict[str, List[RetryAttempt]] = {}
        
    def _initialize_patterns(self) -> Dict[FailureReason, List[FailurePattern]]:
        """Initialize patterns for failure analysis"""
        return {
            FailureReason.WAF_BLOCK: [
                FailurePattern(
                    reason=FailureReason.WAF_BLOCK,
                    pattern=r"(?i)(blocked|forbidden|waf|security|violation)",
                    confidence=0.8,
                    examples=[
                        "Request blocked by security rules",
                        "WAF protection triggered"
                    ]
                ),
            ],
            FailureReason.RATE_LIMIT: [
                FailurePattern(
                    reason=FailureReason.RATE_LIMIT,
                    pattern=r"(?i)(rate limit|too many requests|429)",
                    confidence=0.9,
                    examples=[
                        "Rate limit exceeded",
                        "Too many requests"
                    ]
                ),
            ],
            FailureReason.INPUT_VALIDATION: [
                FailurePattern(
                    reason=FailureReason.INPUT_VALIDATION,
                    pattern=r"(?i)(invalid|validation|malformed|bad request|400)",
                    confidence=0.7,
                    examples=[
                        "Invalid input format",
                        "Input validation failed"
                    ]
                ),
            ],
            # Add more patterns for other failure reasons
        }
        
    async def plan_retry(self, failed_payload: str,
                        response_text: str,
                        context: Dict[str, Any],
                        config: Optional[RetryConfig] = None) -> RetryResult:
        """
        Plan retry strategy based on failure analysis
        
        Args:
            failed_payload: The payload that failed
            response_text: Response/error from the failed attempt
            context: Additional context about the failure
            config: Optional retry configuration
            
        Returns:
            RetryResult with planned retry strategy
        """
        logger.info(f"Planning retry for payload: {failed_payload[:50]}...")
        
        # Use default config if none provided
        config = config or RetryConfig()
        
        try:
            # Analyze failure
            failure_reason, confidence = await self._analyze_failure(
                response_text,
                context
            )
            
            # Select retry strategy
            strategy = await self._select_strategy(
                failure_reason,
                context,
                config
            )
            
            # Calculate next delay
            next_delay = self._calculate_delay(
                failed_payload,
                strategy,
                config
            )
            
            # Modify payload based on strategy
            modified_payload = await self._modify_payload(
                failed_payload,
                strategy,
                failure_reason,
                context
            )
            
            result = RetryResult(
                failure_reason=failure_reason,
                suggested_strategy=strategy,
                modified_payload=modified_payload,
                next_delay=next_delay,
                context=context,
                confidence=confidence
            )
            
            # Record attempt
            self._record_attempt(
                failed_payload,
                modified_payload,
                strategy,
                response_text
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Retry planning failed: {str(e)}")
            return RetryResult(
                failure_reason=FailureReason.UNKNOWN,
                suggested_strategy=RetryStrategy.BACKOFF,
                modified_payload=failed_payload,
                next_delay=config.base_delay,
                context={},
                confidence=0.0
            )
            
    async def _analyze_failure(self, response_text: str,
                             context: Dict[str, Any]) -> Tuple[FailureReason, float]:
        """Analyze failure response to determine reason"""
        best_match = (FailureReason.UNKNOWN, 0.0)
        
        try:
            for reason, patterns in self.failure_patterns.items():
                for pattern in patterns:
                    if re.search(pattern.pattern, response_text):
                        pattern.detection_count += 1
                        if pattern.confidence > best_match[1]:
                            best_match = (reason, pattern.confidence)
                            
            # Use LLM for uncertain cases
            if best_match[1] < 0.6:
                llm_reason = await self._analyze_with_llm(response_text, context)
                if llm_reason:
                    best_match = (llm_reason, 0.7)
                    
            return best_match
            
        except Exception as e:
            logger.error(f"Failure analysis failed: {str(e)}")
            return (FailureReason.UNKNOWN, 0.0)
            
    async def _select_strategy(self, failure_reason: FailureReason,
                             context: Dict[str, Any],
                             config: RetryConfig) -> RetryStrategy:
        """Select appropriate retry strategy"""
        try:
            # Use configured strategies if provided
            if config.allowed_strategies:
                strategies = config.allowed_strategies
            else:
                # Default strategy mapping
                strategies = {
                    FailureReason.WAF_BLOCK: RetryStrategy.WAF_EVASION,
                    FailureReason.RATE_LIMIT: RetryStrategy.BACKOFF,
                    FailureReason.INPUT_VALIDATION: RetryStrategy.ERROR_CORRECTION,
                    FailureReason.AUTH_FAILURE: RetryStrategy.AUTH_REFRESH,
                    FailureReason.TIMEOUT: RetryStrategy.TIMING_ADJUSTMENT,
                    FailureReason.CONNECTION_ERROR: RetryStrategy.PROXY_ROTATION
                }
                
            return strategies.get(failure_reason, RetryStrategy.BACKOFF)
            
        except Exception as e:
            logger.error(f"Strategy selection failed: {str(e)}")
            return RetryStrategy.BACKOFF
            
    def _calculate_delay(self, payload: str,
                        strategy: RetryStrategy,
                        config: RetryConfig) -> float:
        """Calculate delay before next retry"""
        try:
            base_delay = config.base_delay
            attempts = len(self.attempt_history.get(payload, []))
            
            if strategy == RetryStrategy.BACKOFF:
                # Exponential backoff
                delay = base_delay * (2 ** attempts)
            elif strategy == RetryStrategy.RATE_LIMIT:
                # Rate limit handling
                delay = base_delay * (attempts + 1)
            else:
                # Linear backoff for other strategies
                delay = base_delay * attempts
                
            return min(delay, config.max_delay)
            
        except Exception as e:
            logger.error(f"Delay calculation failed: {str(e)}")
            return config.base_delay
            
    async def _modify_payload(self, payload: str,
                            strategy: RetryStrategy,
                            failure_reason: FailureReason,
                            context: Dict[str, Any]) -> str:
        """Modify payload based on selected strategy"""
        try:
            if strategy == RetryStrategy.WAF_EVASION:
                # Use payload evasion system
                results = await self.payload_evasion.evade_waf(
                    payload,
                    context
                )
                if results:
                    return results[0].evaded
                    
            elif strategy == RetryStrategy.ERROR_CORRECTION:
                # Try to fix syntax/validation errors
                return await self._fix_payload_errors(
                    payload,
                    failure_reason,
                    context
                )
                
            elif strategy == RetryStrategy.PAYLOAD_MUTATION:
                # Mutate payload structure
                return await self._mutate_payload(
                    payload,
                    context
                )
                
            return payload
            
        except Exception as e:
            logger.error(f"Payload modification failed: {str(e)}")
            return payload
            
    def _record_attempt(self, original: str,
                       modified: str,
                       strategy: RetryStrategy,
                       response: Optional[str]) -> None:
        """Record retry attempt details"""
        try:
            attempt = RetryAttempt(
                original_payload=original,
                modified_payload=modified,
                strategy=strategy,
                timestamp=datetime.utcnow(),
                success=False,
                response=response
            )
            
            self.attempt_history.setdefault(original, []).append(attempt)
            
        except Exception as e:
            logger.error(f"Failed to record attempt: {str(e)}")
            
    async def _analyze_with_llm(self, response_text: str,
                               context: Dict[str, Any]) -> Optional[FailureReason]:
        """Use LLM to analyze unclear failures"""
        query = f"""Analyze the following error response and determine the most likely failure reason.
Consider the context and classify the failure type.

Response:
{response_text}

Context:
{json.dumps(context, indent=2)}

Return one of: {', '.join(r.value for r in FailureReason)}
"""
        result = generate_response(query)
        try:
            reason = result.strip().lower()
            return FailureReason(reason)
        except Exception:
            return None
            
    async def _fix_payload_errors(self, payload: str,
                                failure_reason: FailureReason,
                                context: Dict[str, Any]) -> str:
        """Try to fix payload errors"""
        query = f"""Fix the following payload that failed due to {failure_reason.value}.
Apply necessary corrections while preserving the payload's purpose.

Payload:
{payload}

Context:
{json.dumps(context, indent=2)}

Return the corrected payload as a string.
"""
        result = generate_response(query)
        try:
            return result.strip() if result else payload
        except Exception:
            return payload
            
    async def _mutate_payload(self, payload: str,
                             context: Dict[str, Any]) -> str:
        """Mutate payload structure"""
        query = f"""Modify the structure of the following payload while preserving its functionality.
Try alternative syntax or equivalent operations.

Payload:
{payload}

Context:
{json.dumps(context, indent=2)}

Return the mutated payload as a string.
"""
        result = generate_response(query)
        try:
            return result.strip() if result else payload
        except Exception:
            return payload
