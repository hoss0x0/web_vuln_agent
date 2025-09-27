"""Advanced safety monitoring system for web vulnerability testing."""

import re
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json

from utils.logger import setup_logger

logger = setup_logger(__name__)

class RiskLevel(Enum):
    """Risk levels for different types of operations"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class SafetyCategory(Enum):
    """Categories of safety checks"""
    DATA_DESTRUCTION = "data_destruction"
    SYSTEM_COMMAND = "system_command"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SENSITIVE_DATA = "sensitive_data"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SERVICE_DISRUPTION = "service_disruption"
    PERSISTENCE = "persistence"
    NETWORK_MANIPULATION = "network_manipulation"

@dataclass
class SafetyPattern:
    """Pattern for identifying safety risks"""
    pattern: str
    category: SafetyCategory
    risk_level: RiskLevel
    description: str
    examples: List[str] = field(default_factory=list)
    detection_count: int = 0
    last_detected: Optional[datetime] = None
    context_patterns: List[str] = field(default_factory=list)

@dataclass
class SafetyCheck:
    """Result of a safety check"""
    is_safe: bool
    risk_level: RiskLevel
    categories: Set[SafetyCategory]
    matches: List[Tuple[str, SafetyPattern]]
    timestamp: datetime
    context: Dict[str, str]

class SafetyMonitor:
    """Advanced safety monitoring system"""
    
    def __init__(self):
        self._initialize_patterns()
        self.check_history: List[SafetyCheck] = []
        self.max_history = 1000
        
    def _initialize_patterns(self) -> None:
        """Initialize safety detection patterns"""
        self.patterns: Dict[SafetyCategory, List[SafetyPattern]] = {
            SafetyCategory.DATA_DESTRUCTION: [
                SafetyPattern(
                    pattern=r"(?i)(DROP\s+(?:TABLE|DATABASE)|DELETE\s+FROM|TRUNCATE\s+TABLE)",
                    category=SafetyCategory.DATA_DESTRUCTION,
                    risk_level=RiskLevel.CRITICAL,
                    description="Database destruction commands",
                    examples=["DROP TABLE users", "DELETE FROM customers"],
                    context_patterns=[
                        r"(?i)success|affected|deleted|dropped",
                        r"(?i)rows?\s+(?:affected|deleted|modified)"
                    ]
                ),
                SafetyPattern(
                    pattern=r"(?i)(rm\s+-\w*(?:rf?|fr)\s+\/|rmdir|shred|unlink)",
                    category=SafetyCategory.DATA_DESTRUCTION,
                    risk_level=RiskLevel.CRITICAL,
                    description="Filesystem destruction commands",
                    examples=["rm -rf /", "shred -u file"],
                    context_patterns=[
                        r"(?i)deleted|removed|no such file",
                        r"(?i)directory not found"
                    ]
                )
            ],
            SafetyCategory.SYSTEM_COMMAND: [
                SafetyPattern(
                    pattern=r"(?i)(exec\(|system\(|shell_exec|popen|subprocess|spawn)",
                    category=SafetyCategory.SYSTEM_COMMAND,
                    risk_level=RiskLevel.HIGH,
                    description="Command execution attempts",
                    examples=["exec('rm -rf /')", "system('wget malware')"],
                    context_patterns=[
                        r"(?i)command|process|executed|running",
                        r"(?i)started|finished|completed"
                    ]
                ),
                SafetyPattern(
                    pattern=r"(?i)(shutdown|reboot|poweroff|halt|init\s+[06])",
                    category=SafetyCategory.SYSTEM_COMMAND,
                    risk_level=RiskLevel.HIGH,
                    description="System control commands",
                    examples=["shutdown -h now", "reboot -f"],
                    context_patterns=[
                        r"(?i)system|service|daemon",
                        r"(?i)stopping|stopped|starting"
                    ]
                )
            ],
            SafetyCategory.PRIVILEGE_ESCALATION: [
                SafetyPattern(
                    pattern=r"(?i)(sudo|su\s+-|runas|setuid|setgid|chmod\s+(?:\+[sS]|7\d{2}))",
                    category=SafetyCategory.PRIVILEGE_ESCALATION,
                    risk_level=RiskLevel.CRITICAL,
                    description="Privilege elevation attempts",
                    examples=["sudo su -", "chmod +s file"],
                    context_patterns=[
                        r"(?i)permission|access|denied|granted",
                        r"(?i)root|admin|superuser"
                    ]
                )
            ],
            SafetyCategory.SENSITIVE_DATA: [
                SafetyPattern(
                    pattern=r"(?i)(password|credit_?card|ssn|social_?security|secret)",
                    category=SafetyCategory.SENSITIVE_DATA,
                    risk_level=RiskLevel.HIGH,
                    description="Sensitive data exposure",
                    examples=["password=123", "ssn=123-45-6789"],
                    context_patterns=[
                        r"(?i)data|information|record|field",
                        r"(?i)leaked|exposed|found"
                    ]
                )
            ],
            SafetyCategory.RESOURCE_EXHAUSTION: [
                SafetyPattern(
                    pattern=r"(?i)(fork\s*bomb|\(\s*:\s*\)|while\s*\(\s*true\s*\))",
                    category=SafetyCategory.RESOURCE_EXHAUSTION,
                    risk_level=RiskLevel.HIGH,
                    description="Resource exhaustion attempts",
                    examples=[":(){ :|:& };:", "while(true)"],
                    context_patterns=[
                        r"(?i)cpu|memory|disk|usage|load",
                        r"(?i)high|full|exceeded"
                    ]
                )
            ],
            SafetyCategory.SERVICE_DISRUPTION: [
                SafetyPattern(
                    pattern=r"(?i)(denial\s*of\s*service|ddos|syn\s*flood|kill\s*-9)",
                    category=SafetyCategory.SERVICE_DISRUPTION,
                    risk_level=RiskLevel.HIGH,
                    description="Service disruption attempts",
                    examples=["ddos attack", "kill -9 1"],
                    context_patterns=[
                        r"(?i)service|process|daemon|server",
                        r"(?i)down|stopped|killed|terminated"
                    ]
                )
            ],
            SafetyCategory.PERSISTENCE: [
                SafetyPattern(
                    pattern=r"(?i)(crontab|systemctl|service|daemon|startup|autorun)",
                    category=SafetyCategory.PERSISTENCE,
                    risk_level=RiskLevel.MEDIUM,
                    description="Persistence mechanism attempts",
                    examples=["crontab -e", "systemctl enable"],
                    context_patterns=[
                        r"(?i)installed|enabled|created",
                        r"(?i)startup|boot|launch"
                    ]
                )
            ],
            SafetyCategory.NETWORK_MANIPULATION: [
                SafetyPattern(
                    pattern=r"(?i)(iptables|route\s+add|ifconfig|tcpdump|wireshark)",
                    category=SafetyCategory.NETWORK_MANIPULATION,
                    risk_level=RiskLevel.MEDIUM,
                    description="Network manipulation attempts",
                    examples=["iptables -F", "route add default"],
                    context_patterns=[
                        r"(?i)network|interface|routing|firewall",
                        r"(?i)changed|modified|configured"
                    ]
                )
            ]
        }

    def is_safe_to_proceed(self, response_text: str,
                          context: Optional[Dict[str, str]] = None) -> SafetyCheck:
        """
        Enhanced safety check with comprehensive pattern matching and context analysis
        
        Args:
            response_text: The text to check for safety violations
            context: Optional additional context about the operation
            
        Returns:
            SafetyCheck object with detailed analysis results
        """
        try:
            matches: List[Tuple[str, SafetyPattern]] = []
            categories: Set[SafetyCategory] = set()
            highest_risk = RiskLevel.INFO
            
            # Check each category's patterns
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    # Check main pattern
                    if re.search(pattern.pattern, response_text, re.IGNORECASE):
                        # Verify with context patterns if available
                        if pattern.context_patterns and context:
                            context_str = json.dumps(context)
                            if any(re.search(cp, context_str, re.IGNORECASE) 
                                 for cp in pattern.context_patterns):
                                self._record_detection(pattern)
                                matches.append((response_text, pattern))
                                categories.add(category)
                                if pattern.risk_level.value > highest_risk.value:
                                    highest_risk = pattern.risk_level
                        else:
                            # No context patterns or no context provided
                            self._record_detection(pattern)
                            matches.append((response_text, pattern))
                            categories.add(category)
                            if pattern.risk_level.value > highest_risk.value:
                                highest_risk = pattern.risk_level
            
            # Create safety check result
            check = SafetyCheck(
                is_safe=len(matches) == 0,
                risk_level=highest_risk,
                categories=categories,
                matches=matches,
                timestamp=datetime.utcnow(),
                context=context or {}
            )
            
            # Record check in history
            self._record_check(check)
            
            # Log significant findings
            if not check.is_safe:
                logger.warning(
                    f"Safety check failed: {len(matches)} matches found "
                    f"with risk level {highest_risk.value}"
                )
                for match, pattern in matches:
                    logger.warning(
                        f"Match in category {pattern.category.value}: {match[:100]}"
                    )
            
            return check
            
        except Exception as e:
            logger.error(f"Safety check failed: {str(e)}")
            # Return conservative result on error
            return SafetyCheck(
                is_safe=False,
                risk_level=RiskLevel.HIGH,
                categories={SafetyCategory.SYSTEM_COMMAND},
                matches=[],
                timestamp=datetime.utcnow(),
                context=context or {}
            )
    
    def _record_detection(self, pattern: SafetyPattern) -> None:
        """Record pattern detection for analysis"""
        try:
            pattern.detection_count += 1
            pattern.last_detected = datetime.utcnow()
        except Exception as e:
            logger.error(f"Failed to record detection: {str(e)}")
    
    def _record_check(self, check: SafetyCheck) -> None:
        """Record safety check in history"""
        try:
            self.check_history.append(check)
            # Maintain maximum history size
            if len(self.check_history) > self.max_history:
                self.check_history = self.check_history[-self.max_history:]
        except Exception as e:
            logger.error(f"Failed to record check: {str(e)}")
    
    def get_detection_stats(self) -> Dict[SafetyCategory, Dict[str, int]]:
        """Get detection statistics by category"""
        try:
            stats = {}
            for category, patterns in self.patterns.items():
                stats[category] = {
                    "total_detections": sum(p.detection_count for p in patterns),
                    "unique_patterns": len(patterns)
                }
            return stats
        except Exception as e:
            logger.error(f"Failed to get detection stats: {str(e)}")
            return {}
