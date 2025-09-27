"""Advanced stop trigger system for vulnerability assessment."""

from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from enum import Enum

from utils.logger import setup_logger

logger = setup_logger(__name__)

class VulnerabilityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(Enum):
    """Types of vulnerabilities to monitor"""
    SQL_INJECTION = "sqli"
    REMOTE_CODE_EXECUTION = "rce"
    XSS = "xss"
    FILE_INCLUSION = "file_inclusion"
    PATH_TRAVERSAL = "path_traversal" 
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    AUTH_BYPASS = "auth_bypass"

@dataclass
class StopConfig:
    """Configuration for stop trigger conditions"""
    max_critical_findings: int = 3
    max_high_findings: int = 5
    max_total_findings: int = 10
    time_window: timedelta = timedelta(minutes=5)
    max_rate: float = 2.0  # findings per second

@dataclass 
class VulnerabilityMetrics:
    """Metrics about found vulnerabilities"""
    count_by_type: Dict[VulnerabilityType, int]
    count_by_level: Dict[VulnerabilityLevel, int]
    first_found: datetime
    last_found: datetime
    
def get_vulnerability_level(vuln_type: str) -> VulnerabilityLevel:
    """Map vulnerability types to severity levels"""
    severity_map = {
        VulnerabilityType.SQL_INJECTION: VulnerabilityLevel.CRITICAL,
        VulnerabilityType.REMOTE_CODE_EXECUTION: VulnerabilityLevel.CRITICAL,
        VulnerabilityType.COMMAND_INJECTION: VulnerabilityLevel.CRITICAL,
        VulnerabilityType.DESERIALIZATION: VulnerabilityLevel.CRITICAL,
        VulnerabilityType.AUTH_BYPASS: VulnerabilityLevel.CRITICAL,
        VulnerabilityType.XXE: VulnerabilityLevel.HIGH,
        VulnerabilityType.FILE_INCLUSION: VulnerabilityLevel.HIGH,
        VulnerabilityType.PATH_TRAVERSAL: VulnerabilityLevel.HIGH,
        VulnerabilityType.SSRF: VulnerabilityLevel.HIGH,
        VulnerabilityType.XSS: VulnerabilityLevel.MEDIUM
    }
    try:
        return severity_map.get(VulnerabilityType(vuln_type), VulnerabilityLevel.LOW)
    except ValueError:
        return VulnerabilityLevel.LOW

def calculate_metrics(findings: List[Dict]) -> VulnerabilityMetrics:
    """Calculate metrics from findings"""
    count_by_type = {vtype: 0 for vtype in VulnerabilityType}
    count_by_level = {level: 0 for level in VulnerabilityLevel}
    
    first_found = datetime.max
    last_found = datetime.min
    
    for finding in findings:
        try:
            vuln_type = VulnerabilityType(finding.get("vulnerability", ""))
            count_by_type[vuln_type] += 1
            
            level = get_vulnerability_level(vuln_type.value)
            count_by_level[level] += 1
            
            timestamp = finding.get("timestamp", datetime.utcnow())
            first_found = min(first_found, timestamp)
            last_found = max(last_found, timestamp)
        except (ValueError, KeyError) as e:
            logger.warning(f"Invalid finding format: {e}")
            continue
            
    return VulnerabilityMetrics(
        count_by_type=count_by_type,
        count_by_level=count_by_level,
        first_found=first_found,
        last_found=last_found
    )

def should_stop(findings: List[Dict], config: Optional[StopConfig] = None) -> bool:
    """
    Determine if testing should stop based on vulnerability findings and metrics
    
    Args:
        findings: List of vulnerability findings
        config: Optional configuration for stop conditions
        
    Returns:
        bool: True if testing should stop, False otherwise
    """
    try:
        # Use default config if none provided
        config = config or StopConfig()
        
        # Calculate metrics
        metrics = calculate_metrics(findings)
        
        # Check critical findings threshold
        if metrics.count_by_level[VulnerabilityLevel.CRITICAL] >= config.max_critical_findings:
            logger.warning("Stopping: Maximum critical findings reached")
            return True
            
        # Check high severity findings threshold
        if metrics.count_by_level[VulnerabilityLevel.HIGH] >= config.max_high_findings:
            logger.warning("Stopping: Maximum high severity findings reached")
            return True
            
        # Check total findings threshold
        total_findings = sum(metrics.count_by_level.values())
        if total_findings >= config.max_total_findings:
            logger.warning("Stopping: Maximum total findings reached")
            return True
            
        # Check finding rate
        if metrics.first_found != datetime.max:
            duration = (metrics.last_found - metrics.first_found).total_seconds()
            if duration > 0:
                rate = total_findings / duration
                if rate > config.max_rate:
                    logger.warning(f"Stopping: Maximum finding rate exceeded ({rate:.2f}/s)")
                    return True
                    
        # Check time window
        if metrics.first_found != datetime.max:
            time_elapsed = datetime.utcnow() - metrics.first_found
            if time_elapsed > config.time_window:
                logger.warning("Stopping: Maximum time window exceeded")
                return True
                
        return False
        
    except Exception as e:
        logger.error(f"Error in stop trigger: {str(e)}")
        # Conservative approach - stop on error
        return True
