import json
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Union, Any, Set
from urllib.parse import urlparse, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from chains.safety.safety_monitor import SafetyMonitor, SafetyViolationError
from chains.waf.waf_detector import WAFDetector
from chains.retry.retry_planner import RetryPlanner
from chains.learning.memory_writer import MemoryWriter
from chains.planning.vulnerability_mapper import VulnerabilityMapper
from chains.payloads.payload_retriever import PayloadRetriever
from chains.payloads.payload_mutator import PayloadMutator
import yaml
from pathlib import Path
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor

from rag_layer.rag_chain import generate_response
from chains.safety.safety_monitor import check_safety_constraints
from chains.waf.waf_detector import detect_waf_presence
from chains.payloads.payload_retriever import PayloadRetriever
from chains.payloads.payload_mutator import PayloadMutator
from chains.payloads.payload_metadata import PayloadAnalyzer
from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    XSS = "xss"
    SQLI = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    IDOR = "idor"
    CSRF = "csrf"
    SSTI = "template_injection"
    NOSQL = "nosql_injection"
    GRAPHQL = "graphql_injection"
    LDAP = "ldap_injection"
    XML = "xml_injection"
    PROTOTYPE = "prototype_pollution"
    BUFFER = "buffer_overflow"
    FORMAT = "format_string"

class AttackType(Enum):
    """Types of attacks"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    BLIND = "blind"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    OUT_OF_BAND = "out_of_band"
    BOOLEAN_BASED = "boolean_based"
    LATERAL = "lateral"
    RACE_CONDITION = "race_condition"
    DOS = "denial_of_service"
    MEMORY_BASED = "memory_based"
    CACHE_BASED = "cache_based"
    PORT_SCAN = "port_scan"
    DATA_EXFIL = "data_exfiltration"

class InjectionMethod(Enum):
    """Types of injection methods"""
    DIRECT = "direct"
    ENCODED = "encoded"
    NESTED = "nested"
    FRAGMENTED = "fragmented"
    UNICODE = "unicode"
    BASE64 = "base64"
    HEX = "hex"
    MULTIPART = "multipart"
    TEMPLATE = "template"
    OBFUSCATED = "obfuscated"
    CONCATENATED = "concatenated"
    RECURSIVE = "recursive"
    POLYGLOT = "polyglot"
    PARAMETER = "parameter"
    HEADER = "header"
    COOKIE = "cookie"

class AttackStage(Enum):
    """Stages of an attack"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"

class AttackStatus(Enum):
    """Status of an attack"""
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    BLOCKED = "blocked"
    DETECTED = "detected"
    UNKNOWN = "unknown"

@dataclass
class AttackStageConfig:
    """Configuration for an attack stage"""
    stage: AttackStage
    required: bool = True
    max_attempts: int = 3
    timeout: int = 300
    dependencies: List[AttackStage] = field(default_factory=list)
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    fallback_stages: List[AttackStage] = field(default_factory=list)
    cleanup_required: bool = True

@dataclass
class AttackTechnique:
    """Specific attack technique configuration"""
    name: str
    description: str
    success_rate: float
    complexity: int
    prerequisites: List[str]
    known_bypasses: List[str]
    target_technologies: List[str]
    references: List[str]
    payload_templates: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackVector:
    """Comprehensive attack vector configuration"""
    id: str
    vulnerability_type: VulnerabilityType
    attack_type: AttackType
    injection_method: InjectionMethod
    stage_configs: Dict[AttackStage, AttackStageConfig]
    techniques: List[AttackTechnique]
    payload_templates: List[str]
    use_vectordb: bool
    escape_techniques: List[str]
    fallback_strategies: List[str]
    detection_methods: List[str]
    status: AttackStatus
    success_probability: float
    estimated_time: int
    required_permissions: List[str]
    target_surfaces: List[str]
    known_defenses: List[str]
    bypass_techniques: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.vulnerability_type.value}:{self.attack_type.value}:{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:16]

class AttackPlanner:
    """Enhanced attack planner with advanced strategies, safety controls and stage management"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vulnerability_mapper = VulnerabilityMapper()
        self.payload_retriever = PayloadRetriever()
        self.payload_mutator = PayloadMutator()
        self.memory_writer = MemoryWriter()
        self.waf_detector = WAFDetector()
        self.retry_planner = RetryPlanner()
        self.safety_monitor = SafetyMonitor()
        self.attack_history: Dict[str, List[AttackVector]] = {}
        self.active_attacks: Dict[str, AttackVector] = {}
        self.stage_handlers: Dict[AttackStage, Callable] = self._initialize_stage_handlers()
        
    def _initialize_stage_handlers(self) -> Dict[AttackStage, Callable]:
        """Initialize handlers for different attack stages"""
        return {
            AttackStage.RECONNAISSANCE: self._handle_recon_stage,
            AttackStage.VULNERABILITY_ANALYSIS: self._handle_vuln_analysis,
            AttackStage.EXPLOITATION: self._handle_exploitation,
            AttackStage.PERSISTENCE: self._handle_persistence,
            AttackStage.CLEANUP: self._handle_cleanup
        }
        
    def _validate_input(self, mapped_input: Dict) -> bool:
        """
        Validate the input parameters for attack planning
        
        Args:
            mapped_input: Dictionary containing input parameters
            
        Returns:
            bool: True if input is valid, False otherwise
        """
        required_fields = ["parameter", "context", "vulnerability_type", "target_url"]
        
        try:
            if not all(field in mapped_input for field in required_fields):
                logger.error(f"Missing required fields: {required_fields}")
                return False
                
            if not isinstance(mapped_input["vulnerability_type"], str):
                logger.error("vulnerability_type must be a string")
                return False
                
            if not mapped_input["parameter"]:
                logger.error("parameter cannot be empty")
                return False

            # Validate target URL format
            if not re.match(r'^https?://', mapped_input["target_url"]):
                logger.error("target_url must be a valid HTTP(S) URL")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Input validation error: {str(e)}")
            return False

    async def _initialize_attack_vector(self, target_url: str, vulnerability_type: VulnerabilityType) -> AttackVector:
        """Initialize a new attack vector
        
        Args:
            target_url: Target URL
            vulnerability_type: Type of vulnerability
            
        Returns:
            AttackVector: Initial attack vector configuration
        """
        logger.info(f"Initializing attack vector for {vulnerability_type.value}")
        try:
            # Generate unique ID
            vector_id = hashlib.sha256(
                f"{vulnerability_type.value}:{target_url}:{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:16]
            
            # Choose initial attack type
            attack_type = await self._select_attack_type(vulnerability_type, target_url)
            
            # Select injection method based on WAF
            waf_detected = await self.waf_detector.detect(target_url)
            injection_method = self._choose_injection_method(waf_detected)
            
            # Create attack vector
            return AttackVector(
                id=vector_id,
                vulnerability_type=vulnerability_type,
                attack_type=attack_type,
                injection_method=injection_method,
                stage_configs={},  # Will be populated later
                techniques=[],     # Will be populated later
                payload_templates=[],  # Will be populated later
                use_vectordb=True,
                escape_techniques=[],  # Will be populated later
                fallback_strategies=[], # Will be populated later
                detection_methods=self._get_detection_methods(attack_type),
                status=AttackStatus.PLANNED,
                success_probability=0.0,  # Will be calculated later
                estimated_time=0,
                required_permissions=[],
                target_surfaces=[],
                known_defenses=[],
                bypass_techniques=[]
            )
            
        except Exception as e:
            logger.error(f"Attack vector initialization failed: {str(e)}")
            raise

    async def _build_stage_configs(self, vulnerability_type: VulnerabilityType) -> Dict[AttackStage, AttackStageConfig]:
        """Build configurations for all attack stages
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            Dict[AttackStage, AttackStageConfig]: Stage configurations
        """
        configs = {}
        
        # Configure reconnaissance
        configs[AttackStage.RECONNAISSANCE] = AttackStageConfig(
            stage=AttackStage.RECONNAISSANCE,
            required=True,
            max_attempts=3,
            timeout=300,
            dependencies=[],
            success_criteria={
                "technologies": {"operator": "not_empty"},
                "waf": {"operator": "exists"}
            }
        )
        
        # Configure vulnerability analysis
        configs[AttackStage.VULNERABILITY_ANALYSIS] = AttackStageConfig(
            stage=AttackStage.VULNERABILITY_ANALYSIS,
            required=True,
            max_attempts=2,
            timeout=600,
            dependencies=[AttackStage.RECONNAISSANCE],
            success_criteria={
                "attack_surface": {"operator": "not_empty"},
                "success_probability": {"operator": "greater_than", "value": 0.3}
            }
        )
        
        # Configure exploitation
        configs[AttackStage.EXPLOITATION] = AttackStageConfig(
            stage=AttackStage.EXPLOITATION,
            required=True,
            max_attempts=5,
            timeout=900,
            dependencies=[AttackStage.VULNERABILITY_ANALYSIS],
            success_criteria={
                "payload_executed": True,
                "attack_successful": True
            }
        )
        
        # Optionally configure persistence
        if self.config.get("enable_persistence", False):
            configs[AttackStage.PERSISTENCE] = AttackStageConfig(
                stage=AttackStage.PERSISTENCE,
                required=False,
                max_attempts=2,
                timeout=600,
                dependencies=[AttackStage.EXPLOITATION],
                success_criteria={
                    "persistence_established": True
                }
            )
            
        # Configure cleanup
        configs[AttackStage.CLEANUP] = AttackStageConfig(
            stage=AttackStage.CLEANUP,
            required=True,
            max_attempts=1,
            timeout=300,
            dependencies=[AttackStage.EXPLOITATION],
            success_criteria={
                "artifacts_removed": True,
                "results_recorded": True
            }
        )
        
        return configs
        
    async def _select_attack_type(self, vulnerability_type: VulnerabilityType, target_url: str) -> AttackType:
        """Select most appropriate attack type
        
        Args:
            vulnerability_type: Type of vulnerability
            target_url: Target URL
            
        Returns:
            AttackType: Selected attack type
        """
        try:
            # Analyze target capabilities
            tech_info = await self._analyze_technologies(target_url)
            
            if vulnerability_type == VulnerabilityType.SQLI:
                # Prefer UNION-based if error messages enabled
                if tech_info.get("error_messages_enabled", False):
                    return AttackType.UNION_BASED
                # Fall back to boolean-based if not
                return AttackType.BOOLEAN_BASED
                
            elif vulnerability_type == VulnerabilityType.XSS:
                # Check for SPA/heavy JS usage
                if await self._is_spa(target_url):
                    return AttackType.DOM
                # Default to reflected
                return AttackType.REFLECTED
                
            elif vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
                # Prefer blind if no output shown
                if not tech_info.get("command_output_reflected", False):
                    return AttackType.BLIND
                return AttackType.DIRECT
                
            # Default per vulnerability type
            defaults = {
                VulnerabilityType.SSRF: AttackType.OUT_OF_BAND,
                VulnerabilityType.PATH_TRAVERSAL: AttackType.DIRECT,
                VulnerabilityType.XXE: AttackType.OUT_OF_BAND,
                VulnerabilityType.DESERIALIZATION: AttackType.DIRECT
            }
            
            return defaults.get(vulnerability_type, AttackType.DIRECT)
            
        except Exception as e:
            logger.error(f"Attack type selection failed: {str(e)}")
            return AttackType.DIRECT
            
    def _choose_injection_method(self, waf_info: Dict[str, Any]) -> InjectionMethod:
        """Choose appropriate injection method
        
        Args:
            waf_info: WAF detection results
            
        Returns:
            InjectionMethod: Selected injection method
        """
        try:
            if not waf_info.get("detected", False):
                return InjectionMethod.DIRECT
                
            # WAF detected, choose evasion method
            waf_type = waf_info.get("type", "unknown").lower()
            
            # Type-specific bypasses
            if "cloudflare" in waf_type:
                return InjectionMethod.UNICODE
            elif "modsecurity" in waf_type:
                return InjectionMethod.MULTIPART
            elif "f5" in waf_type:
                return InjectionMethod.ENCODED
                
            # Default evasion
            return InjectionMethod.ENCODED
            
        except Exception as e:
            logger.error(f"Injection method selection failed: {str(e)}")
            return InjectionMethod.DIRECT
            
    async def _analyze_target_surface(self, target_url: str, attack_vector: AttackVector) -> Dict[str, Any]:
        """Analyze target attack surface
        
        Args:
            target_url: Target URL
            attack_vector: Current attack vector
            
        Returns:
            Dict with surface info and defenses
        """
        try:
            surface_info = {"surfaces": [], "defenses": []}
            
            # Analyze input vectors
            input_vectors = await self._identify_input_vectors(target_url)
            surface_info["surfaces"].extend(input_vectors)
            
            # Check for specific vulnerabilities
            if attack_vector.vulnerability_type == VulnerabilityType.XSS:
                js_contexts = await self._find_js_contexts(target_url)
                surface_info["surfaces"].extend(js_contexts)
                
            elif attack_vector.vulnerability_type == VulnerabilityType.SQLI:
                db_inputs = await self._find_database_inputs(target_url)
                surface_info["surfaces"].extend(db_inputs)
                
            # Analyze defenses
            waf_info = await self.waf_detector.detect(target_url)
            if waf_info.get("detected"):
                surface_info["defenses"].append(f"waf_{waf_info['type']}")
                
            security_headers = await self._check_security_headers(target_url)
            surface_info["defenses"].extend(security_headers)
            
            return surface_info
            
        except Exception as e:
            logger.error(f"Target surface analysis failed: {str(e)}")
            return {"surfaces": [], "defenses": []}
            
    async def _calculate_success_probability(self, attack_vector: AttackVector) -> float:
        """Calculate probability of attack success
        
        Args:
            attack_vector: Attack vector to analyze
            
        Returns:
            float: Success probability from 0.0 to 1.0
        """
        try:
            base_probability = 0.5
            
            # Adjust based on techniques
            if attack_vector.techniques:
                technique_prob = max(t.success_rate for t in attack_vector.techniques)
                base_probability = technique_prob
                
            # Defense penalty
            defense_count = len(attack_vector.known_defenses)
            defense_penalty = min(defense_count * 0.1, 0.5)
            base_probability -= defense_penalty
            
            # Surface bonus
            surface_count = len(attack_vector.target_surfaces)
            surface_bonus = min(surface_count * 0.05, 0.3)
            base_probability += surface_bonus
            
            # Adjust for injection method
            method_multipliers = {
                InjectionMethod.DIRECT: 1.0,
                InjectionMethod.ENCODED: 0.9,
                InjectionMethod.UNICODE: 0.8,
                InjectionMethod.MULTIPART: 0.85,
                InjectionMethod.NESTED: 0.7,
                InjectionMethod.FRAGMENTED: 0.6
            }
            base_probability *= method_multipliers.get(attack_vector.injection_method, 0.8)
            
            return max(min(base_probability, 1.0), 0.0)
            
        except Exception as e:
            logger.error(f"Success probability calculation failed: {str(e)}")
            return 0.0
            
    async def _find_js_contexts(self, target_url: str) -> List[str]:
        """Find JavaScript execution contexts
        
        Args:
            target_url: Target URL
            
        Returns:
            List[str]: Found JS contexts
        """
        # TODO: Implement JS context discovery
        return ["inline_script", "event_handler"]
        
    async def _find_database_inputs(self, target_url: str) -> List[str]:
        """Find potential database input points
        
        Args:
            target_url: Target URL
            
        Returns:
            List[str]: Found DB inputs
        """
        # TODO: Implement DB input discovery
        return ["query_param", "post_data"]
        
    async def _check_security_headers(self, target_url: str) -> List[str]:
        """Check for security headers
        
        Args:
            target_url: Target URL
            
        Returns:
            List[str]: Found security headers
        """
        # TODO: Implement security header checks
        return ["x-frame-options", "content-security-policy"]

    def _get_detection_methods(self, attack_type: AttackType) -> List[str]:
        """Get detection methods based on attack type"""
        methods = {
            AttackType.REFLECTED: ["response_grep", "content_comparison"],
            AttackType.BLIND: ["time_analysis", "boolean_analysis"],
            AttackType.OUT_OF_BAND: ["dns_monitoring", "http_callback"],
            AttackType.STORED: ["persistent_grep", "state_comparison"],
            AttackType.DOM: ["dom_observation", "event_monitoring"],
            AttackType.TIME_BASED: ["timing_analysis", "delay_correlation"],
            AttackType.ERROR_BASED: ["error_analysis", "stack_trace_parsing"],
            AttackType.UNION_BASED: ["column_count", "data_extraction"],
            AttackType.BOOLEAN_BASED: ["true_false_analysis", "conditional_responses"],
            AttackType.LATERAL: ["network_mapping", "service_discovery"],
            AttackType.RACE_CONDITION: ["timing_windows", "concurrency_analysis"]
        }
        return methods.get(attack_type, ["response_analysis", "behavior_monitoring"])
        
    async def _handle_recon_stage(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Handle the reconnaissance stage of the attack"""
        logger.info(f"Starting reconnaissance for {target_url}")
        try:
            # Initialize stage configuration
            stage_config = attack_vector.stage_configs[AttackStage.RECONNAISSANCE]
            start_time = datetime.utcnow()
            
            # Analyze target technologies
            tech_info = await self._analyze_technologies(target_url)
            attack_vector.metadata["technologies"] = tech_info
            
            # Port scanning if allowed
            if self.config.get("enable_port_scan", False):
                ports = await self._scan_ports(target_url)
                attack_vector.metadata["open_ports"] = ports
                
            # Directory enumeration
            if self.config.get("enable_dir_enum", False):
                dirs = await self._enumerate_directories(target_url)
                attack_vector.metadata["directories"] = dirs
                
            # WAF detection
            waf_info = await self.waf_detector.detect(target_url)
            attack_vector.metadata["waf"] = waf_info
            
            # Analyze rate limiting
            rate_limits = await self._analyze_rate_limits(target_url)
            attack_vector.metadata["rate_limits"] = rate_limits
            
            # Check success criteria
            success = await self._check_stage_success(
                stage_config,
                attack_vector.metadata
            )
            
            # Update stage timing
            attack_vector.metadata["recon_time"] = (datetime.utcnow() - start_time).seconds
            
            return success
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {str(e)}")
            return False
            
    async def _analyze_technologies(self, target_url: str) -> Dict[str, Any]:
        """Analyze technologies used by the target"""
        try:
            tech_info = {}
            
            # Basic server info
            server_info = await self._get_server_info(target_url)
            tech_info["server"] = server_info
            
            # Framework detection
            framework = await self._detect_framework(target_url)
            if framework:
                tech_info["framework"] = framework
                
            # Frontend analysis
            frontend = await self._analyze_frontend(target_url)
            tech_info["frontend"] = frontend
            
            # API technology
            api_tech = await self._detect_api_tech(target_url)
            if api_tech:
                tech_info["api"] = api_tech
                
            # Security measures
            security = await self._analyze_security(target_url)
            tech_info["security"] = security
            
            return tech_info
            
        except Exception as e:
            logger.error(f"Technology analysis failed: {str(e)}")
            return {}
            
    async def _scan_ports(self, target_url: str) -> List[Dict[str, Any]]:
        """Scan for open ports and services"""
        try:
            parsed = urlparse(target_url)
            host = parsed.hostname
            
            # TODO: Implement actual port scanning
            # For now return mock data
            return [
                {"port": 80, "service": "http", "state": "open"},
                {"port": 443, "service": "https", "state": "open"}
            ]
            
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            return []
            
    async def _enumerate_directories(self, target_url: str) -> List[str]:
        """Enumerate directories on target"""
        try:
            # TODO: Implement directory enumeration
            # For now return mock data
            return ["/admin", "/api", "/uploads"]
            
        except Exception as e:
            logger.error(f"Directory enumeration failed: {str(e)}")
            return []
            
    async def _analyze_rate_limits(self, target_url: str) -> Dict[str, Any]:
        """Analyze rate limiting configurations"""
        try:
            limits = {}
            
            # Test request rates
            for rate in [10, 50, 100]:  # requests per second
                has_limit = await self._test_rate(target_url, rate)
                if has_limit:
                    limits["max_rate"] = rate
                    break
                    
            # Check cooldown periods
            if "max_rate" in limits:
                cooldown = await self._find_cooldown(target_url)
                limits["cooldown"] = cooldown
                
            return limits
            
        except Exception as e:
            logger.error(f"Rate limit analysis failed: {str(e)}")
            return {}
            
    async def _analyze_frontend(self, target_url: str) -> Dict[str, Any]:
        """Analyze frontend technologies and frameworks"""
        try:
            frontend = {}
            
            # Check for common JS frameworks
            js_frameworks = await self._detect_js_frameworks(target_url)
            if js_frameworks:
                frontend["frameworks"] = js_frameworks
                
            # Analyze DOM complexity
            dom_info = await self._analyze_dom(target_url)
            frontend["dom"] = dom_info
            
            # Check for SPAs
            if await self._is_spa(target_url):
                frontend["type"] = "spa"
                
            # Detect UI libraries
            ui_libs = await self._detect_ui_libraries(target_url)
            if ui_libs:
                frontend["libraries"] = ui_libs
                
            return frontend
            
        except Exception as e:
            logger.error(f"Frontend analysis failed: {str(e)}")
            return {}
            
    async def _detect_js_frameworks(self, target_url: str) -> List[str]:
        """Detect JavaScript frameworks in use"""
        # TODO: Implement actual detection
        return ["react", "jquery"]
        
    async def _analyze_dom(self, target_url: str) -> Dict[str, Any]:
        """Analyze DOM structure and complexity"""
        # TODO: Implement DOM analysis
        return {
            "elements": 1000,
            "depth": 8,
            "dynamic": True
        }
        
    async def _is_spa(self, target_url: str) -> bool:
        """Detect if target is a Single Page Application"""
        # TODO: Implement SPA detection
        return False
        
    async def _detect_ui_libraries(self, target_url: str) -> List[str]:
        """Detect UI component libraries"""
        # TODO: Implement library detection
        return ["bootstrap", "material-ui"]
        
    async def _test_rate(self, target_url: str, rate: int) -> bool:
        """Test if target has rate limiting at specified request rate"""
        # TODO: Implement rate testing
        return rate >= 50
        
    async def _find_cooldown(self, target_url: str) -> int:
        """Find cooldown period after hitting rate limit"""
        # TODO: Implement cooldown detection
        return 60  # seconds
        
    async def _check_stage_success(self, stage_config: AttackStageConfig, metadata: Dict) -> bool:
        """Check if stage success criteria are met"""
        try:
            criteria = stage_config.success_criteria
            
            # Check each criterion
            for key, value in criteria.items():
                if key not in metadata:
                    logger.warning(f"Missing metadata for criterion: {key}")
                    if stage_config.required:
                        return False
                    continue
                    
                if not self._matches_criterion(metadata[key], value):
                    logger.warning(f"Failed criterion {key}: {metadata[key]} != {value}")
                    if stage_config.required:
                        return False
                        
            return True
            
        except Exception as e:
            logger.error(f"Stage success check failed: {str(e)}")
            return False
            
    def _matches_criterion(self, value: Any, criterion: Any) -> bool:
        """Check if a value matches a success criterion"""
        try:
            if isinstance(criterion, dict):
                operator = criterion.get("operator", "equals")
                target = criterion.get("value")
                
                if operator == "equals":
                    return value == target
                elif operator == "contains":
                    return target in value
                elif operator == "greater_than":
                    return value > target
                elif operator == "less_than":
                    return value < target
                elif operator == "not_empty":
                    return bool(value)
                else:
                    logger.warning(f"Unknown criterion operator: {operator}")
                    return False
            else:
                return value == criterion
                
        except Exception as e:
            logger.error(f"Criterion matching failed: {str(e)}")
            return False
            
    async def execute_attack(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Execute attack stages and track progress"""
        try:
            attack_vector.status = AttackStatus.IN_PROGRESS
            start_time = datetime.utcnow()
            
            # Execute stages in order
            for stage in AttackStage:
                if stage not in attack_vector.stage_configs:
                    continue
                    
                logger.info(f"Executing stage: {stage.value}")
                
                # Check dependencies
                if not await self._check_dependencies(stage, attack_vector):
                    logger.error(f"Dependencies not met for stage {stage.value}")
                    attack_vector.status = AttackStatus.FAILED
                    return False
                    
                # Get stage handler
                handler = self.stage_handlers.get(stage)
                if not handler:
                    logger.error(f"No handler for stage {stage.value}")
                    continue
                    
                # Execute stage
                success = await handler(attack_vector, target_url)
                
                if not success:
                    # Try fallback if available
                    fallback_success = await self._try_fallback(stage, attack_vector, target_url)
                    if not fallback_success and attack_vector.stage_configs[stage].required:
                        attack_vector.status = AttackStatus.FAILED
                        return False
                        
            # Update timing and status
            attack_vector.estimated_time = (datetime.utcnow() - start_time).seconds
            attack_vector.status = AttackStatus.SUCCESSFUL
            return True
            
        except Exception as e:
            logger.error(f"Attack execution failed: {str(e)}")
            attack_vector.status = AttackStatus.FAILED
            return False
            
    async def _check_dependencies(self, stage: AttackStage, attack_vector: AttackVector) -> bool:
        """Check if stage dependencies are met"""
        try:
            stage_config = attack_vector.stage_configs[stage]
            
            for dep_stage in stage_config.dependencies:
                # Check if dependent stage exists and succeeded
                if dep_stage not in attack_vector.stage_configs:
                    logger.error(f"Missing dependent stage: {dep_stage.value}")
                    return False
                    
                dep_success = attack_vector.metadata.get(f"{dep_stage.value}_success", False)
                if not dep_success:
                    logger.error(f"Dependent stage {dep_stage.value} did not succeed")
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Dependency check failed: {str(e)}")
            return False
            
    async def _try_fallback(self, stage: AttackStage, attack_vector: AttackVector, target_url: str) -> bool:
        """Try fallback stages after main stage failure"""
        try:
            stage_config = attack_vector.stage_configs[stage]
            
            for fallback_stage in stage_config.fallback_stages:
                logger.info(f"Trying fallback stage: {fallback_stage.value}")
                
                handler = self.stage_handlers.get(fallback_stage)
                if not handler:
                    continue
                    
                if await handler(attack_vector, target_url):
                    logger.info(f"Fallback stage {fallback_stage.value} succeeded")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Fallback execution failed: {str(e)}")
            return False
            
    async def _handle_vuln_analysis(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Handle the vulnerability analysis stage"""
        logger.info(f"Starting vulnerability analysis for {attack_vector.vulnerability_type}")
        try:
            # Map vulnerability to specific techniques
            attack_vector.techniques = await self._map_attack_techniques(
                attack_vector.vulnerability_type
            )
            
            # Analyze target surface
            surface_info = await self._analyze_attack_surface(target_url, attack_vector)
            attack_vector.target_surfaces = surface_info["surfaces"]
            attack_vector.known_defenses = surface_info["defenses"]
            
            # Estimate success probability
            attack_vector.success_probability = await self._calculate_success_probability(
                attack_vector
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {str(e)}")
            return False
            
    async def _handle_exploitation(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Handle the exploitation stage"""
        logger.info(f"Starting exploitation for {attack_vector.id}")
        try:
            # Prepare payloads
            payloads = await self._prepare_payloads(attack_vector)
            if not payloads:
                logger.error("No valid payloads generated")
                return False
                
            # Execute attack techniques
            for technique in attack_vector.techniques:
                success = await self._execute_technique(
                    technique, 
                    payloads, 
                    target_url,
                    attack_vector
                )
                if success:
                    attack_vector.status = AttackStatus.SUCCESSFUL
                    return True
                    
            # If all techniques failed, try fallback strategies
            if attack_vector.fallback_strategies:
                return await self._execute_fallback_strategies(attack_vector, target_url)
                
            attack_vector.status = AttackStatus.FAILED
            return False
            
        except Exception as e:
            logger.error(f"Exploitation failed: {str(e)}")
            attack_vector.status = AttackStatus.FAILED
            return False
            
    async def _handle_persistence(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Handle the persistence stage if applicable"""
        if not self.config.get("enable_persistence", False):
            logger.info("Persistence stage disabled by configuration")
            return True
            
        logger.info(f"Starting persistence stage for {attack_vector.id}")
        try:
            if attack_vector.status != AttackStatus.SUCCESSFUL:
                logger.warning("Cannot establish persistence - exploitation was not successful")
                return False
                
            # Implement persistence logic based on vulnerability type
            persistence_result = await self._establish_persistence(attack_vector, target_url)
            
            if persistence_result:
                attack_vector.metadata["persistence"] = persistence_result
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Persistence stage failed: {str(e)}")
            return False
            
    async def _handle_cleanup(self, attack_vector: AttackVector, target_url: str) -> bool:
        """Handle the cleanup stage"""
        logger.info(f"Starting cleanup for {attack_vector.id}")
        try:
            # Remove any artifacts
            await self._remove_artifacts(attack_vector, target_url)
            
            # Document attack results
            await self.memory_writer.write_attack_result(attack_vector)
            
            # Update attack history
            self.attack_history.setdefault(target_url, []).append(attack_vector)
            
            # Remove from active attacks
            self.active_attacks.pop(attack_vector.id, None)
            
            return True
            
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
            return False
            
    async def _get_server_info(self, target_url: str) -> Dict[str, Any]:
        """Get basic server information
        
        Args:
            target_url: Target URL
            
        Returns:
            Dict with server information
        """
        try:
            # TODO: Implement server info gathering
            # For now return mock data
            return {
                "type": "nginx",
                "version": "1.18.0",
                "os": "linux",
                "headers": ["server", "x-powered-by"]
            }
        except Exception as e:
            logger.error(f"Failed to get server info: {str(e)}")
            return {}
            
    async def _detect_framework(self, target_url: str) -> Optional[str]:
        """Detect web framework in use
        
        Args:
            target_url: Target URL
            
        Returns:
            Framework name if detected
        """
        try:
            # TODO: Implement framework detection
            # For now return mock data
            return "django"
        except Exception as e:
            logger.error(f"Framework detection failed: {str(e)}")
            return None
            
    async def _detect_api_tech(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Detect API technologies
        
        Args:
            target_url: Target URL
            
        Returns:
            API technology details if detected
        """
        try:
            # TODO: Implement API technology detection
            # For now return mock data
            return {
                "type": "rest",
                "auth": "jwt",
                "formats": ["json"]
            }
        except Exception as e:
            logger.error(f"API detection failed: {str(e)}")
            return None
            
    async def _analyze_security(self, target_url: str) -> Dict[str, Any]:
        """Analyze security measures
        
        Args:
            target_url: Target URL
            
        Returns:
            Dict with security details
        """
        try:
            security = {}
            
            # Headers
            headers = await self._check_security_headers(target_url)
            if headers:
                security["headers"] = headers
                
            # CORS
            cors = await self._check_cors(target_url)
            if cors:
                security["cors"] = cors
                
            # Auth
            auth = await self._check_auth(target_url)
            if auth:
                security["auth"] = auth
                
            return security
            
        except Exception as e:
            logger.error(f"Security analysis failed: {str(e)}")
            return {}
            
    async def _check_cors(self, target_url: str) -> Dict[str, Any]:
        """Check CORS configuration
        
        Args:
            target_url: Target URL
            
        Returns:
            Dict with CORS details
        """
        try:
            # TODO: Implement CORS checking
            # For now return mock data
            return {
                "allow_origin": ["*"],
                "allow_methods": ["GET", "POST"],
                "allow_headers": ["*"]
            }
        except Exception as e:
            logger.error(f"CORS check failed: {str(e)}")
            return {}
            
    async def _check_auth(self, target_url: str) -> Dict[str, Any]:
        """Check authentication mechanisms
        
        Args:
            target_url: Target URL
            
        Returns:
            Dict with auth details
        """
        try:
            # TODO: Implement auth checking
            # For now return mock data
            return {
                "type": "cookie",
                "mechanisms": ["session"],
                "csrf_protection": True
            }
        except Exception as e:
            logger.error(f"Auth check failed: {str(e)}")
            return {}
            
    async def _prepare_payloads(self, attack_vector: AttackVector) -> List[str]:
        """Prepare attack payloads
        
        Args:
            attack_vector: Attack vector to prepare payloads for
            
        Returns:
            List of prepared payloads
        """
        try:
            # Get base payloads
            payloads = await self.payload_retriever.get_payloads(
                attack_vector.vulnerability_type,
                attack_vector.attack_type
            )
            
            # Apply mutations based on techniques
            for technique in attack_vector.techniques:
                payloads = await self.payload_mutator.mutate_payloads(
                    payloads,
                    technique.parameters
                )
                
            # Encode based on injection method
            encoded_payloads = []
            for payload in payloads:
                encoded = await self._encode_payload(
                    payload,
                    attack_vector.injection_method
                )
                encoded_payloads.append(encoded)
                
            return encoded_payloads
            
        except Exception as e:
            logger.error(f"Payload preparation failed: {str(e)}")
            return []
            
    async def _encode_payload(self, payload: str, method: InjectionMethod) -> str:
        """Encode payload based on injection method
        
        Args:
            payload: Raw payload
            method: Injection method
            
        Returns:
            Encoded payload
        """
        try:
            # TODO: Implement proper encoding
            return payload
            
        except Exception as e:
            logger.error(f"Payload encoding failed: {str(e)}")
            return payload
            
    async def _execute_technique(self, technique: AttackTechnique, 
                               payloads: List[str],
                               target_url: str,
                               attack_vector: AttackVector) -> bool:
        """Execute an attack technique
        
        Args:
            technique: Technique to execute
            payloads: Prepared payloads
            target_url: Target URL
            attack_vector: Current attack vector
            
        Returns:
            bool: True if successful
        """
        try:
            logger.info(f"Executing technique: {technique.name}")
            
            # Try each payload
            for payload in payloads:
                # Execute payload
                result = await self._execute_payload(
                    payload,
                    technique,
                    target_url,
                    attack_vector
                )
                
                if result.get("success"):
                    # Record successful payload
                    attack_vector.metadata["successful_payload"] = payload
                    attack_vector.metadata["execution_result"] = result
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Technique execution failed: {str(e)}")
            return False
            
    async def _execute_payload(self, payload: str,
                             technique: AttackTechnique,
                             target_url: str,
                             attack_vector: AttackVector) -> Dict[str, Any]:
        """Execute a single payload
        
        Args:
            payload: Payload to execute
            technique: Current technique
            target_url: Target URL
            attack_vector: Current attack vector
            
        Returns:
            Dict with execution results
        """
        try:
            # TODO: Implement actual payload execution
            # For now return mock result
            return {
                "success": False,
                "response": None,
                "error": "Not implemented"
            }
            
        except Exception as e:
            logger.error(f"Payload execution failed: {str(e)}")
            return {"success": False, "error": str(e)}
            
    async def _execute_fallback_strategies(self, attack_vector: AttackVector,
                                        target_url: str) -> bool:
        """Execute fallback attack strategies
        
        Args:
            attack_vector: Attack vector with fallback strategies
            target_url: Target URL
            
        Returns:
            bool: True if any fallback succeeds
        """
        try:
            for strategy in attack_vector.fallback_strategies:
                # Get fallback technique
                technique = self._get_fallback_technique(strategy)
                if not technique:
                    continue
                    
                # Prepare fallback payloads
                payloads = await self._prepare_fallback_payloads(
                    technique,
                    attack_vector
                )
                
                # Execute technique
                if await self._execute_technique(
                    technique,
                    payloads,
                    target_url,
                    attack_vector
                ):
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Fallback execution failed: {str(e)}")
            return False
            
    def _get_fallback_technique(self, strategy: str) -> Optional[AttackTechnique]:
        """Get technique for fallback strategy
        
        Args:
            strategy: Strategy name
            
        Returns:
            AttackTechnique if found
        """
        try:
            # TODO: Implement proper fallback mapping
            # For now return mock technique
            return AttackTechnique(
                name=f"fallback_{strategy}",
                description="Fallback technique",
                success_rate=0.4,
                complexity=2,
                prerequisites=[],
                known_bypasses=[],
                target_technologies=[],
                references=[],
                payload_templates=[]
            )
        except Exception as e:
            logger.error(f"Failed to get fallback technique: {str(e)}")
            return None
            
    async def _prepare_fallback_payloads(self, technique: AttackTechnique,
                                       attack_vector: AttackVector) -> List[str]:
        """Prepare payloads for fallback technique
        
        Args:
            technique: Fallback technique
            attack_vector: Current attack vector
            
        Returns:
            List of prepared payloads
        """
        try:
            # TODO: Implement fallback payload preparation
            # For now return mock payloads
            return ["fallback_payload_1", "fallback_payload_2"]
            
        except Exception as e:
            logger.error(f"Fallback payload preparation failed: {str(e)}")
            return []
            
    async def _establish_persistence(self, attack_vector: AttackVector,
                                  target_url: str) -> Optional[Dict[str, Any]]:
        """Establish persistence on target
        
        Args:
            attack_vector: Successfully executed attack vector
            target_url: Target URL
            
        Returns:
            Dict with persistence details if successful
        """
        try:
            # TODO: Implement persistence logic
            # For now return mock result
            return {
                "type": "file_upload",
                "location": "/uploads/shell.php",
                "access_method": "http"
            }
            
        except Exception as e:
            logger.error(f"Failed to establish persistence: {str(e)}")
            return None
            
    async def _remove_artifacts(self, attack_vector: AttackVector,
                             target_url: str) -> bool:
        """Remove attack artifacts
        
        Args:
            attack_vector: Executed attack vector
            target_url: Target URL
            
        Returns:
            bool: True if cleanup successful
        """
        try:
            # TODO: Implement artifact removal
            # For now return mock success
            return True
            
        except Exception as e:
            logger.error(f"Artifact removal failed: {str(e)}")
            return False

    async def plan_attack(self, target_url: str, vulnerability_type: VulnerabilityType) -> AttackVector:
        """Plan a comprehensive attack strategy
        
        This method orchestrates the complete attack planning process, including:
        - Safety validation
        - Attack vector initialization 
        - Stage configuration
        - Technique mapping
        - Surface analysis
        - Success probability calculation
        
        Args:
            target_url: Target URL to attack
            vulnerability_type: Type of vulnerability to exploit
            
        Returns:
            AttackVector: Configured attack vector with stages and strategies
        
        Raises:
            SafetyViolationError: If attack plan violates safety constraints
            ValueError: If invalid input parameters
            Exception: For other errors during planning
        """
        logger.info(f"Planning attack for {vulnerability_type.value} on {target_url}")
        try:
            # Safety check before proceeding
            if not await self.safety_monitor.is_safe_to_proceed(target_url):
                raise SafetyViolationError("Attack plan violates safety constraints")
                
            # Create attack vector
            attack_vector = await self._initialize_attack_vector(target_url, vulnerability_type)
            attack_vector.stage_configs = await self._build_stage_configs(vulnerability_type)
            
            # Map vulnerability to attack techniques
            attack_vector.techniques = await self.vulnerability_mapper.map_vulnerabilities(
                target_url, vulnerability_type
            )
            
            # Analyze target surface and defenses
            surface_info = await self._analyze_target_surface(target_url, attack_vector)
            attack_vector.target_surfaces = surface_info["surfaces"]
            attack_vector.known_defenses = surface_info["defenses"]
            
            # Estimate success probability
            attack_vector.success_probability = await self._calculate_success_probability(
                attack_vector
            )
            
            # Record attack plan
            self.active_attacks[attack_vector.id] = attack_vector
            
            return attack_vector
            
        except Exception as e:
            logger.error(f"Attack planning failed: {str(e)}")
            raise
            
    async def plan_attack_llm(self, mapped_inputs: List[Dict]) -> List[Dict]:
        """Build customized attack plans using LLM
        
        Args:
            mapped_inputs: List of dictionaries containing input parameters
            
        Returns:
            List[Dict]: List of attack plans
        """
        if not mapped_inputs:
            logger.error("No inputs provided for attack planning")
            return []

        attack_plans = []
        
        for input_data in mapped_inputs:
            try:
                if not self._validate_input(input_data):
                    continue

                # Check safety constraints
                if self.safety_checks and not check_safety_constraints(input_data):
                    logger.warning(f"Safety check failed for input: {input_data['parameter']}")
                    continue

                # Detect WAF if enabled
                if self.waf_detection:
                    input_data["waf_detected"] = detect_waf_presence(input_data.get("target_url"))

                # Generate attack vector
                attack_vector = self._generate_attack_vector(
                    input_data["vulnerability_type"],
                    input_data.get("context", {})
                )

                # Generate LLM query with enhanced context
                query = f"""Generate a detailed attack plan for:
                Parameter: {input_data['parameter']}
                Vulnerability: {attack_vector.vulnerability_type.value}
                Attack Type: {attack_vector.attack_type.value}
                Injection Method: {attack_vector.injection_method.value}
                
                Consider:
                - Escape techniques: {', '.join(attack_vector.escape_techniques)}
                - Fallback strategies: {', '.join(attack_vector.fallback_strategies)}
                - Detection methods: {', '.join(attack_vector.detection_methods)}
                
                Additional Context:
                {json.dumps(input_data.get('context', {}), indent=2)}
                """

                # Get LLM response
                response = generate_response(query)
                
                try:
                    plan = json.loads(response) if isinstance(response, str) else response
                except json.JSONDecodeError:
                    logger.error("Failed to parse LLM response as JSON")
                    continue

                # Enhance plan with attack vector details
                plan.update({
                    "attack_vector": {
                        "type": attack_vector.vulnerability_type.value,
                        "method": attack_vector.attack_type.value,
                        "injection": attack_vector.injection_method.value,
                        "payload_template": attack_vector.payload_template,
                        "escape_techniques": attack_vector.escape_techniques,
                        "fallback_strategies": attack_vector.fallback_strategies,
                        "detection_methods": attack_vector.detection_methods
                    }
                })

                attack_plans.append(plan)

            except Exception as e:
                logger.error(f"Error processing input {input_data.get('parameter')}: {str(e)}")
                continue

        return attack_plans
