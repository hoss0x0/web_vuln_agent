"""Advanced WAF evasion techniques and strategies."""

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import base64
import html
from urllib.parse import quote, unquote

from rag_layer.rag_chain import generate_response
from chains.waf.waf_detector import WAFDetector
from utils.logger import setup_logger

logger = setup_logger(__name__)

class EvasionTechnique(Enum):
    """Types of evasion techniques"""
    ENCODING = "encoding"
    CASE_VARIATION = "case_variation"
    COMMENT_INSERTION = "comment_insertion"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENCODE = "html_encode"
    CONCATENATION = "concatenation"
    WHITESPACE = "whitespace"
    NULL_BYTE = "null_byte"
    PARAMETER_POLLUTION = "parameter_pollution"
    HEADER_MANIPULATION = "header_manipulation"

class EncodeType(Enum):
    """Types of payload encoding"""
    BASE64 = "base64"
    URL = "url"
    HTML = "html"
    UNICODE = "unicode"
    HEX = "hex"
    OCTAL = "octal"
    MIXED = "mixed"

@dataclass
class EvasionPattern:
    """Pattern for WAF evasion"""
    technique: EvasionTechnique
    pattern: str
    replacement: str
    success_rate: float = 0.0
    detection_count: int = 0
    bypass_count: int = 0

@dataclass
class EvasionResult:
    """Result of an evasion attempt"""
    original: str
    evaded: str
    technique: EvasionTechnique
    encode_type: Optional[EncodeType]
    success: bool = False
    detected_by: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    
@dataclass
class EvasionConfig:
    """Configuration for evasion attempts"""
    max_attempts: int = 5
    encode_types: List[EncodeType] = field(default_factory=list)
    techniques: List[EvasionTechnique] = field(default_factory=list)
    max_payload_length: int = 2048
    preserve_functionality: bool = True
    timeout: float = 10.0

class PayloadEvasion:
    """Advanced WAF evasion engine"""
    
    def __init__(self):
        self.waf_detector = WAFDetector()
        self.patterns: Dict[EvasionTechnique, List[EvasionPattern]] = self._initialize_patterns()
        self.success_history: Dict[str, List[EvasionResult]] = {}
        
    def _initialize_patterns(self) -> Dict[EvasionTechnique, List[EvasionPattern]]:
        """Initialize evasion patterns for different techniques"""
        patterns = {
            EvasionTechnique.ENCODING: [
                EvasionPattern(
                    technique=EvasionTechnique.ENCODING,
                    pattern=r'[<>]',
                    replacement='\\x{:02x}'
                ),
            ],
            EvasionTechnique.CASE_VARIATION: [
                EvasionPattern(
                    technique=EvasionTechnique.CASE_VARIATION,
                    pattern=r'script',
                    replacement=r'sCrIpT'
                ),
            ],
            EvasionTechnique.COMMENT_INSERTION: [
                EvasionPattern(
                    technique=EvasionTechnique.COMMENT_INSERTION,
                    pattern=r'(\w+)',
                    replacement=r'\1/*!*/\1'
                ),
            ],
            # Add more patterns for other techniques
        }
        return patterns
        
    async def evade_waf(self, payload: str, context: Dict[str, Any],
                       config: Optional[EvasionConfig] = None) -> List[EvasionResult]:
        """
        Attempt to evade WAF detection using multiple techniques
        
        Args:
            payload: Original payload to evade
            context: Attack context
            config: Optional evasion configuration
            
        Returns:
            List of evasion results
        """
        logger.info(f"Starting WAF evasion for payload: {payload[:50]}...")
        
        # Use default config if none provided
        config = config or EvasionConfig()
        
        results = []
        attempts = 0
        
        # Get WAF fingerprint
        waf_info = await self.waf_detector.detect(context.get("target_url", ""))
        
        while attempts < config.max_attempts:
            try:
                # Try different evasion techniques
                for technique in config.techniques or EvasionTechnique:
                    # Skip if we've exceeded attempts
                    if attempts >= config.max_attempts:
                        break
                        
                    # Apply technique
                    evaded = await self._apply_technique(
                        payload,
                        technique,
                        context,
                        waf_info
                    )
                    
                    # Try different encodings if specified
                    if config.encode_types:
                        for encode_type in config.encode_types:
                            encoded = self._encode_payload(evaded, encode_type)
                            results.append(
                                await self._test_evasion(
                                    payload,
                                    encoded,
                                    technique,
                                    encode_type,
                                    context
                                )
                            )
                            attempts += 1
                    else:
                        # Test without encoding
                        results.append(
                            await self._test_evasion(
                                payload,
                                evaded,
                                technique,
                                None,
                                context
                            )
                        )
                        attempts += 1
                        
                    # Break if we found a successful evasion
                    if results and results[-1].success:
                        break
                        
            except Exception as e:
                logger.error(f"Evasion attempt failed: {str(e)}")
                continue
                
        # Update success history
        self._update_history(payload, results)
        
        # Return all results sorted by success
        return sorted(results, key=lambda r: r.success, reverse=True)
        
    async def _apply_technique(self, payload: str,
                             technique: EvasionTechnique,
                             context: Dict[str, Any],
                             waf_info: Dict[str, Any]) -> str:
        """Apply an evasion technique to payload"""
        patterns = self.patterns.get(technique, [])
        evaded = payload
        
        # Apply each pattern for the technique
        for pattern in patterns:
            try:
                if technique == EvasionTechnique.ENCODING:
                    evaded = self._apply_encoding(evaded, pattern)
                elif technique == EvasionTechnique.CASE_VARIATION:
                    evaded = self._apply_case_variation(evaded, pattern)
                elif technique == EvasionTechnique.COMMENT_INSERTION:
                    evaded = self._apply_comment_insertion(evaded, pattern)
                elif technique == EvasionTechnique.UNICODE_ENCODE:
                    evaded = self._apply_unicode_encode(evaded, pattern)
                # Add more technique handlers
                
            except Exception as e:
                logger.error(f"Pattern application failed: {str(e)}")
                continue
                
        # Try AI-based mutation if other techniques fail
        if evaded == payload:
            evaded = await self._mutate_with_llm(payload, context, technique)
            
        return evaded
        
    def _apply_encoding(self, payload: str, pattern: EvasionPattern) -> str:
        """Apply encoding-based evasion"""
        try:
            # Replace characters with hex encoding
            return re.sub(pattern.pattern,
                        lambda m: pattern.replacement.format(ord(m.group(0))),
                        payload)
        except Exception as e:
            logger.error(f"Encoding failed: {str(e)}")
            return payload
            
    def _apply_case_variation(self, payload: str, pattern: EvasionPattern) -> str:
        """Apply case variation evasion"""
        try:
            # Alternate case of matched words
            return re.sub(pattern.pattern,
                        lambda m: ''.join(c.upper() if i % 2 else c.lower()
                                        for i, c in enumerate(m.group(0))),
                        payload)
        except Exception as e:
            logger.error(f"Case variation failed: {str(e)}")
            return payload
            
    def _apply_comment_insertion(self, payload: str, pattern: EvasionPattern) -> str:
        """Apply comment insertion evasion"""
        try:
            # Insert comments between characters
            return re.sub(pattern.pattern, pattern.replacement, payload)
        except Exception as e:
            logger.error(f"Comment insertion failed: {str(e)}")
            return payload
            
    def _apply_unicode_encode(self, payload: str, pattern: EvasionPattern) -> str:
        """Apply Unicode encoding evasion"""
        try:
            # Convert to Unicode escapes
            return ''.join(f'\\u{ord(c):04x}' if re.match(pattern.pattern, c) else c
                         for c in payload)
        except Exception as e:
            logger.error(f"Unicode encoding failed: {str(e)}")
            return payload
            
    def _encode_payload(self, payload: str, encode_type: EncodeType) -> str:
        """Encode payload using specified encoding"""
        try:
            if encode_type == EncodeType.BASE64:
                return base64.b64encode(payload.encode()).decode()
            elif encode_type == EncodeType.URL:
                return quote(payload)
            elif encode_type == EncodeType.HTML:
                return html.escape(payload)
            elif encode_type == EncodeType.UNICODE:
                return payload.encode('unicode_escape').decode()
            elif encode_type == EncodeType.HEX:
                return ''.join(f'\\x{ord(c):02x}' for c in payload)
            elif encode_type == EncodeType.OCTAL:
                return ''.join(f'\\{ord(c):03o}' for c in payload)
            elif encode_type == EncodeType.MIXED:
                # Use mix of encodings
                encoded = payload
                encoded = quote(encoded)
                encoded = base64.b64encode(encoded.encode()).decode()
                return encoded
            return payload
            
        except Exception as e:
            logger.error(f"Payload encoding failed: {str(e)}")
            return payload
            
    async def _test_evasion(self, original: str,
                           evaded: str,
                           technique: EvasionTechnique,
                           encode_type: Optional[EncodeType],
                           context: Dict[str, Any]) -> EvasionResult:
        """Test if evasion attempt is successful"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # TODO: Implement actual WAF testing
            # For now return mock result
            success = True
            detected_by = []
            
            return EvasionResult(
                original=original,
                evaded=evaded,
                technique=technique,
                encode_type=encode_type,
                success=success,
                detected_by=detected_by,
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Evasion testing failed: {str(e)}")
            return EvasionResult(
                original=original,
                evaded=evaded,
                technique=technique,
                encode_type=encode_type,
                success=False,
                detected_by=["error"],
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
    async def _mutate_with_llm(self, payload: str,
                              context: Dict[str, Any],
                              technique: EvasionTechnique) -> str:
        """Use LLM to generate evasion variants"""
        query = f"""Mutate the following payload to bypass WAF filters using {technique.value}.

Payload:
{payload}

Context:
{json.dumps(context, indent=2)}

Return a JSON list of evasion variants.
"""
        result = generate_response(query)
        try:
            variants = json.loads(result) if isinstance(result, str) else result
            return variants[0] if variants else payload
        except Exception as e:
            logger.error(f"LLM mutation failed: {str(e)}")
            return payload
            
    def _update_history(self, payload: str, results: List[EvasionResult]) -> None:
        """Update evasion success history"""
        self.success_history.setdefault(payload, []).extend(results)
        
        # Update pattern success rates
        for result in results:
            if not result.technique:
                continue
                
            patterns = self.patterns.get(result.technique, [])
            for pattern in patterns:
                pattern.detection_count += 1
                if result.success:
                    pattern.bypass_count += 1
                pattern.success_rate = pattern.bypass_count / pattern.detection_count
                
    def get_best_technique(self, payload: str) -> Optional[EvasionTechnique]:
        """Get most successful technique for similar payloads"""
        if payload not in self.success_history:
            return None
            
        # Count successes per technique
        success_counts = {}
        for result in self.success_history[payload]:
            if result.success and result.technique:
                success_counts[result.technique] = success_counts.get(result.technique, 0) + 1
                
        # Return technique with most successes
        return max(success_counts.items(), key=lambda x: x[1])[0] if success_counts else None
