import json
import logging
import asyncio
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import logging
import asyncio
import hashlib
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from chains.execution.payload_injector import inject_payload
from chains.safety.safety_monitor import SafetyMonitor
from chains.safety.stop_trigger import StopTrigger
from chains.waf.waf_detector import WafDetector
from chains.retry.payload_evasion import PayloadEvasion
from utils.logger import setup_logger

logger = setup_logger(__name__)

class InjectionLocation(Enum):
    """Supported injection locations in request"""
    URL_PATH = "url_path"
    QUERY_PARAM = "query_param"
    BODY_PARAM = "body_param"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"
    XML = "xml"
    MULTIPART = "multipart"

class InjectionMethod(Enum):
    """Supported injection methods"""
    REPLACE = "replace"
    APPEND = "append"
    PREPEND = "prepend"
    WRAP = "wrap"
    NESTED = "nested"

@dataclass
class InjectionPoint:
    """Details about where and how to inject payload"""
    location: InjectionLocation
    parameter: str
    method: InjectionMethod
    encoding: Optional[str] = None
    prefix: Optional[str] = None
    suffix: Optional[str] = None
    depth: int = 0

@dataclass
class InjectionResult:
    """Result of payload injection attempt"""
    success: bool
    response: Optional[Dict] = None
    error: Optional[str] = None
    injection_point: Optional[InjectionPoint] = None
    evasion_applied: Optional[List[str]] = None
    request_hash: Optional[str] = None
    timestamp: Optional[str] = None

class RequestInjector:
    """Enhanced request injection with advanced features and safety controls"""

    def __init__(self):
        self.safety_monitor = SafetyMonitor()
        self.stop_trigger = StopTrigger()
        self.waf_detector = WafDetector()
        self.payload_evasion = PayloadEvasion()
        self.max_retries = 3
        self.retry_delay = 1

    async def inject_and_send(
        self,
        session: object,
        parsed_request: Dict,
        injection_plan: Dict,
        payload: str,
        context: Optional[Dict] = None
    ) -> InjectionResult:
        """
        Inject payload into request and send with safety checks and evasion
        
        Args:
            session: HTTP session object
            parsed_request: Parsed request details
            injection_plan: Injection strategy details
            payload: Payload to inject
            context: Additional context for injection
            
        Returns:
            InjectionResult containing attempt details and response
        """
        try:
            # Validate inputs
            self._validate_inputs(parsed_request, injection_plan, payload)
            
            # Create injection point
            injection_point = self._create_injection_point(injection_plan)
            
            # Safety check
            if not self.safety_monitor.check_injection(
                parsed_request, injection_point, payload
            ):
                return InjectionResult(
                    success=False,
                    error="Safety check failed",
                    injection_point=injection_point
                )
            
            # Check for WAF
            if await self.waf_detector.is_waf_present(parsed_request["url"]):
                logger.warning("WAF detected, applying evasion techniques")
                payload = await self._apply_evasion_techniques(payload, context)
            
            # Track request for idempotency
            request_hash = self._generate_request_hash(
                parsed_request, injection_point, payload
            )
            
            # Attempt injection with retries
            for attempt in range(self.max_retries):
                try:
                    # Inject payload
                    modified_request = self._inject_payload(
                        parsed_request.copy(),
                        injection_point,
                        payload
                    )
                    
                    # Send request
                    response = await self._send_request(
                        session, modified_request, context
                    )
                    
                    # Check if WAF blocked
                    if self.waf_detector.is_blocked(response):
                        if attempt < self.max_retries - 1:
                            logger.warning(f"WAF blocked request, attempt {attempt + 1}")
                            payload = self.payload_evasion.evolve_payload(
                                payload, response
                            )
                            await asyncio.sleep(self.retry_delay)
                            continue
                    
                    return InjectionResult(
                        success=True,
                        response=response,
                        injection_point=injection_point,
                        evasion_applied=self.payload_evasion.get_applied_techniques(),
                        request_hash=request_hash,
                        timestamp=str(datetime.now())
                    )
                    
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        raise
                    await asyncio.sleep(self.retry_delay)
            
        except Exception as e:
            logger.error(f"Injection failed: {str(e)}")
            return InjectionResult(
                success=False,
                error=str(e),
                injection_point=injection_point
            )

    def _validate_inputs(
        self, parsed_request: Dict, injection_plan: Dict, payload: str
    ) -> None:
        """Validate input parameters"""
        if not isinstance(parsed_request, dict):
            raise ValueError("parsed_request must be a dictionary")
            
        if not isinstance(injection_plan, dict):
            raise ValueError("injection_plan must be a dictionary")
            
        if not isinstance(payload, str):
            raise ValueError("payload must be a string")
            
        required_fields = ["url", "method"]
        if not all(field in parsed_request for field in required_fields):
            raise ValueError(f"parsed_request missing required fields: {required_fields}")
            
        required_plan_fields = ["target_param", "location"]
        if not all(field in injection_plan for field in required_plan_fields):
            raise ValueError(f"injection_plan missing required fields: {required_plan_fields}")

    def _create_injection_point(self, injection_plan: Dict) -> InjectionPoint:
        """Create injection point from plan"""
        try:
            location = InjectionLocation(injection_plan["location"].lower())
        except ValueError:
            raise ValueError(f"Invalid injection location: {injection_plan['location']}")
            
        return InjectionPoint(
            location=location,
            parameter=injection_plan["target_param"],
            method=InjectionMethod(injection_plan.get("method", "replace").lower()),
            encoding=injection_plan.get("encoding"),
            prefix=injection_plan.get("prefix"),
            suffix=injection_plan.get("suffix"),
            depth=injection_plan.get("depth", 0)
        )

    async def _apply_evasion_techniques(
        self, payload: str, context: Optional[Dict]
    ) -> str:
        """Apply WAF evasion techniques to payload"""
        evasion_chain = [
            self.payload_evasion.encode_payload,
            self.payload_evasion.randomize_payload,
            self.payload_evasion.fragment_payload
        ]
        
        modified_payload = payload
        for technique in evasion_chain:
            try:
                modified_payload = await technique(modified_payload, context)
            except Exception as e:
                logger.warning(f"Evasion technique failed: {str(e)}")
                
        return modified_payload

    def _generate_request_hash(
        self, parsed_request: Dict, injection_point: InjectionPoint, payload: str
    ) -> str:
        """Generate unique hash for request tracking"""
        components = [
            parsed_request["url"],
            parsed_request["method"],
            injection_point.parameter,
            injection_point.location.value,
            payload
        ]
        return hashlib.sha256(
            json.dumps(components, sort_keys=True).encode()
        ).hexdigest()

    def _inject_payload(
        self, request: Dict, injection_point: InjectionPoint, payload: str
    ) -> Dict:
        """Inject payload into request at specified location"""
        if injection_point.location == InjectionLocation.URL_PATH:
            request["url"] = self._inject_url_path(
                request["url"], payload, injection_point
            )
            
        elif injection_point.location == InjectionLocation.QUERY_PARAM:
            request["url"] = self._inject_query_param(
                request["url"], injection_point.parameter, payload, injection_point
            )
            
        elif injection_point.location == InjectionLocation.BODY_PARAM:
            if "body" not in request:
                request["body"] = {}
            request["body"] = self._inject_body_param(
                request["body"], injection_point.parameter, payload, injection_point
            )
            
        elif injection_point.location == InjectionLocation.HEADER:
            if "headers" not in request:
                request["headers"] = {}
            request["headers"][injection_point.parameter] = self._apply_injection_method(
                request["headers"].get(injection_point.parameter, ""),
                payload,
                injection_point
            )
            
        elif injection_point.location == InjectionLocation.JSON:
            if "body" not in request:
                request["body"] = {}
            request["body"] = self._inject_json_payload(
                request["body"], injection_point.parameter, payload, injection_point
            )
            
        return request

    def _inject_url_path(
        self, url: str, payload: str, injection_point: InjectionPoint
    ) -> str:
        """Inject payload into URL path"""
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        
        if injection_point.method == InjectionMethod.REPLACE:
            path_parts[-1] = payload
        elif injection_point.method == InjectionMethod.APPEND:
            path_parts[-1] = path_parts[-1] + payload
        elif injection_point.method == InjectionMethod.PREPEND:
            path_parts[-1] = payload + path_parts[-1]
            
        new_path = "/".join(path_parts)
        return urlunparse(parsed._replace(path=new_path))

    def _inject_query_param(
        self, url: str, param: str, payload: str, injection_point: InjectionPoint
    ) -> str:
        """Inject payload into URL query parameter"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        query_params[param] = [self._apply_injection_method(
            query_params.get(param, [""])[0],
            payload,
            injection_point
        )]
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _inject_body_param(
        self, body: Dict, param: str, payload: str, injection_point: InjectionPoint
    ) -> Dict:
        """Inject payload into request body parameter"""
        if isinstance(body, dict):
            body[param] = self._apply_injection_method(
                body.get(param, ""),
                payload,
                injection_point
            )
        return body

    def _inject_json_payload(
        self, body: Dict, param_path: str, payload: str, injection_point: InjectionPoint
    ) -> Dict:
        """Inject payload into nested JSON structure"""
        if not isinstance(body, dict):
            body = {}
            
        current = body
        path_parts = param_path.split(".")
        
        # Navigate to nested location
        for i, part in enumerate(path_parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
            
        # Inject at final location
        current[path_parts[-1]] = self._apply_injection_method(
            current.get(path_parts[-1], ""),
            payload,
            injection_point
        )
        
        return body

    def _apply_injection_method(
        self, original: str, payload: str, injection_point: InjectionPoint
    ) -> str:
        """Apply injection method to combine original value and payload"""
        if injection_point.method == InjectionMethod.REPLACE:
            result = payload
        elif injection_point.method == InjectionMethod.APPEND:
            result = original + payload
        elif injection_point.method == InjectionMethod.PREPEND:
            result = payload + original
        elif injection_point.method == InjectionMethod.WRAP:
            result = f"{injection_point.prefix or ''}{payload}{injection_point.suffix or ''}"
        elif injection_point.method == InjectionMethod.NESTED:
            depth = injection_point.depth
            result = payload
            for _ in range(depth):
                result = f"{injection_point.prefix or ''}{result}{injection_point.suffix or ''}"
        else:
            result = payload
            
        return result

    async def _send_request(
        self, session: object, request: Dict, context: Optional[Dict]
    ) -> Dict:
        """Send request with injection"""
        return await inject_payload(
            session,
            request,
            request.get("target_param"),
            request.get("payload"),
            request.get("location")
        )

def inject_and_send(
    session: object,
    parsed_request: Dict,
    injection_plan: Dict,
    payload: str
) -> Dict:
    """Legacy wrapper for backward compatibility"""
    injector = RequestInjector()
    return asyncio.run(
        injector.inject_and_send(session, parsed_request, injection_plan, payload)
    )
