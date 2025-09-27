import asyncio
import logging
import time
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from chains.initialization.session_bootstrap import bootstrap_session
from chains.interception.request_parser import parse_request
from chains.interception.input_discovery import discover_inputs_llm
from chains.interception.impact_scorer import score_inputs_llm
from chains.planning.vulnerability_mapper import map_vulnerability_llm
from chains.planning.attack_planner import AttackPlanner
from chains.payloads.payload_retriever import get_payloads
from chains.payloads.payload_mutator import mutate_payload_llm
from chains.execution.payload_injector import inject_payload
from chains.evaluation.response_analyzer import analyze_response_llm
from chains.reporting.report_builder import ReportBuilder
from chains.safety.safety_monitor import SafetyMonitor
from chains.safety.stop_trigger import StopTrigger
from chains.retry.retry_planner import RetryPlanner
from chains.waf.waf_detector import WafDetector
from chains.learning.memory_writer import MemoryWriter
from chains.learning.pii_masker import PIIMasker
from utils.logger import setup_logger
from utils.helpers import Timer

logger = setup_logger(__name__)

@dataclass
class ScanConfig:
    """Configuration for the scanning agent"""
    max_retries: int = 3
    timeout: int = 300  # 5 minutes
    concurrent_requests: int = 10
    safety_checks: bool = True
    waf_detection: bool = True
    learn_from_results: bool = True
    mask_pii: bool = True
    save_evidence: bool = True
    detailed_logging: bool = True

@dataclass
class ScanStatus:
    """Track scanning progress and statistics"""
    start_time: datetime
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    vulnerabilities_found: int = 0
    current_phase: str = "initializing"
    error_count: int = 0
    remaining_retries: int = 0

class WebVulnerabilityAgent:
    """Enhanced web vulnerability scanning agent with advanced features"""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.status = None
        self.stop_trigger = StopTrigger()
        self.safety_monitor = SafetyMonitor()
        self.retry_planner = RetryPlanner()
        self.waf_detector = WafDetector()
        self.memory_writer = MemoryWriter()
        self.pii_masker = PIIMasker()
        self.attack_planner = AttackPlanner()
        self.report_builder = ReportBuilder()
        self.executor = ThreadPoolExecutor(max_workers=self.config.concurrent_requests)

    async def run_agent(self, raw_request: Dict) -> List[Dict]:
        """
        Main entry point for the vulnerability scanning agent
        
        Args:
            raw_request: Raw HTTP request dictionary
            
        Returns:
            List of vulnerability findings
        """
        try:
            with Timer() as timer:
                self.status = ScanStatus(start_time=datetime.now())
                
                # Initialize session and safety checks
                logger.info("Initializing scan session...")
                if not await self._initialize_scan(raw_request):
                    return []

                # Process request and discover inputs
                self.status.current_phase = "input_discovery"
                parsed_request = await self._process_request(raw_request)
                if not parsed_request:
                    return []

                # Plan and execute attacks
                self.status.current_phase = "attack_execution"
                findings = await self._execute_attack_plans(parsed_request)

                # Generate reports
                self.status.current_phase = "reporting"
                await self._generate_reports(findings, parsed_request["url"])

                # Update learning system
                if self.config.learn_from_results:
                    await self._update_learning_system(findings)

                logger.info(f"Scan completed in {timer.duration:.2f}s")
                logger.info(f"Found {len(findings)} vulnerabilities")
                
                return findings

        except Exception as e:
            logger.error(f"Critical error in scan: {str(e)}")
            return []
        finally:
            await self._cleanup()

    async def _initialize_scan(self, raw_request: Dict) -> bool:
        """Initialize scan session and perform preliminary checks"""
        try:
            # Bootstrap session
            self.session = bootstrap_session()
            
            # Check safety constraints
            if self.config.safety_checks and not self.safety_monitor.check_request(raw_request):
                logger.error("Safety check failed - scan aborted")
                return False
                
            # Detect WAF
            if self.config.waf_detection:
                waf_info = await self.waf_detector.detect(raw_request["url"])
                if waf_info.detected:
                    logger.warning(f"WAF detected: {waf_info.name}")
                    
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {str(e)}")
            return False

    async def _process_request(self, raw_request: Dict) -> Optional[Dict]:
        """Process and analyze the raw request"""
        try:
            # Parse request
            parsed = parse_request(raw_request)
            if not parsed:
                return None
                
            # Discover inputs
            inputs = await self._run_with_retry(
                discover_inputs_llm, parsed,
                "Input discovery failed"
            )
            
            # Score input impact
            scored = await self._run_with_retry(
                score_inputs_llm, parsed, inputs,
                "Input scoring failed"
            )
            
            # Map vulnerabilities
            mapped = await self._run_with_retry(
                map_vulnerability_llm, scored,
                "Vulnerability mapping failed"
            )
            
            return mapped
            
        except Exception as e:
            logger.error(f"Request processing failed: {str(e)}")
            return None

    async def _execute_attack_plans(self, parsed_request: Dict) -> List[Dict]:
        """Plan and execute attacks with retry support"""
        findings = []
        
        try:
            # Generate attack plans
            plans = self.attack_planner.plan_attack_llm(parsed_request)
            
            # Execute plans concurrently
            async def execute_plan(plan):
                payloads = await self._get_payloads(plan)
                for payload in payloads:
                    if await self.stop_trigger.should_stop():
                        break
                        
                    finding = await self._execute_payload(plan, payload, parsed_request)
                    if finding:
                        findings.append(finding)
                        
            await asyncio.gather(*[execute_plan(plan) for plan in plans])
            
        except Exception as e:
            logger.error(f"Attack execution failed: {str(e)}")
            
        return findings

    async def _get_payloads(self, plan: Dict) -> List[str]:
        """Get and mutate payloads for a plan"""
        try:
            base_payloads = get_payloads(plan["vulnerability"], plan["injection"])
            
            mutated = []
            for payload in base_payloads:
                variants = await self._run_with_retry(
                    mutate_payload_llm,
                    payload["payload"],
                    plan,
                    "Payload mutation failed"
                )
                mutated.extend(variants)
                
            return mutated
            
        except Exception as e:
            logger.error(f"Payload generation failed: {str(e)}")
            return []

    async def _execute_payload(self, plan: Dict, payload: str, parsed_request: Dict) -> Optional[Dict]:
        """Execute a single payload with safety checks and analysis"""
        try:
            # Safety check
            if not self.safety_monitor.check_payload(payload):
                return None
                
            # Inject payload
            response = await self._run_with_retry(
                inject_payload,
                self.session,
                parsed_request,
                plan["target_param"],
                payload,
                plan["location"]
            )
            
            if not response:
                return None
                
            # Analyze response
            analysis = await self._run_with_retry(
                analyze_response_llm,
                response.text,
                payload,
                "Response analysis failed"
            )
            
            if analysis["executed"]:
                finding = {
                    "param": plan["target_param"],
                    "vulnerability": plan["vulnerability"],
                    "payload": payload,
                    "evidence": analysis["evidence"],
                    "notes": analysis["notes"],
                    "severity": analysis.get("severity", "Medium"),
                    "timestamp": datetime.now().isoformat(),
                    "request": {
                        "method": parsed_request["method"],
                        "url": parsed_request["url"],
                        "headers": parsed_request.get("headers", {})
                    }
                }
                
                # Mask PII if configured
                if self.config.mask_pii:
                    finding = self.pii_masker.mask_data(finding)
                    
                return finding
                
        except Exception as e:
            logger.error(f"Payload execution failed: {str(e)}")
            
        return None

    async def _generate_reports(self, findings: List[Dict], target_url: str) -> None:
        """Generate various report formats"""
        try:
            # Generate JSON report
            self.report_builder.build_report(findings, target_url)
            
            # Generate Markdown report
            self.report_builder.build_markdown_report(findings, target_url)
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

    async def _update_learning_system(self, findings: List[Dict]) -> None:
        """Update the learning system with scan results"""
        if self.config.learn_from_results:
            try:
                await self.memory_writer.store_findings(findings)
            except Exception as e:
                logger.error(f"Learning system update failed: {str(e)}")

    async def _run_with_retry(self, func, *args, error_message: str = "Operation failed") -> Any:
        """Run a function with retry logic"""
        for attempt in range(self.config.max_retries):
            try:
                return await func(*args) if asyncio.iscoroutinefunction(func) else func(*args)
            except Exception as e:
                logger.warning(f"{error_message} (attempt {attempt + 1}/{self.config.max_retries}): {str(e)}")
                if attempt == self.config.max_retries - 1:
                    raise

    async def _cleanup(self) -> None:
        """Cleanup resources"""
        try:
            self.executor.shutdown(wait=True)
            await self.memory_writer.close()
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")

def run_agent(raw_request: Dict) -> List[Dict]:
    """Synchronous wrapper for backward compatibility"""
    agent = WebVulnerabilityAgent()
    return asyncio.run(agent.run_agent(raw_request))
