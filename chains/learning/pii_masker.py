import re
import logging
from pathlib import Path
import yaml
from typing import Dict, List, Optional, Set, Pattern, Union
from dataclasses import dataclass
import json
from enum import Enum
import hashlib

from utils.logger import setup_logger

logger = setup_logger(__name__)

class PIIType(Enum):
    """Types of PII data"""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"
    NAME = "name"
    DOB = "date_of_birth"
    IP_ADDRESS = "ip_address"
    PASSPORT = "passport"
    DRIVING_LICENSE = "driving_license"
    BANK_ACCOUNT = "bank_account"
    CUSTOM = "custom"

@dataclass
class MaskingPattern:
    """Pattern for masking PII data"""
    type: PIIType
    pattern: str
    replacement: str
    description: str
    priority: int
    enabled: bool = True
    
    def compile(self) -> Pattern:
        """Compile regex pattern"""
        try:
            return re.compile(self.pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex pattern for {self.type}: {str(e)}")
            raise ValueError(f"Invalid regex pattern for {self.type}: {str(e)}")

class PIIMasker:
    """Enhanced PII masker with configurable patterns and validation"""
    
    def __init__(self):
        self.patterns: List[MaskingPattern] = []
        self.compiled_patterns: Dict[PIIType, Pattern] = {}
        self.masked_count: Dict[PIIType, int] = {}
        self.sensitive_types: Set[PIIType] = set()
        self._load_config()
        self._compile_patterns()
        
    def _load_config(self) -> None:
        """Load masking configuration"""
        try:
            config_path = Path("config/masking_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                
            # Load patterns from config
            for pattern_config in config.get("patterns", []):
                pattern = MaskingPattern(
                    type=PIIType(pattern_config["type"]),
                    pattern=pattern_config["pattern"],
                    replacement=pattern_config["replacement"],
                    description=pattern_config["description"],
                    priority=pattern_config["priority"],
                    enabled=pattern_config.get("enabled", True)
                )
                self.patterns.append(pattern)
                
            # Load sensitive types
            sensitive_types = config.get("sensitive_types", [])
            self.sensitive_types = {PIIType(t) for t in sensitive_types}
                
        except Exception as e:
            logger.error(f"Failed to load masking config: {str(e)}")
            self._load_default_patterns()
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "patterns": [
                {
                    "type": "email",
                    "pattern": r"\b[\w.-]+@[\w.-]+\.\w+\b",
                    "replacement": "[EMAIL]",
                    "description": "Email addresses",
                    "priority": 1,
                    "enabled": True
                },
                {
                    "type": "phone",
                    "pattern": r"\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b",
                    "replacement": "[PHONE]",
                    "description": "Phone numbers",
                    "priority": 2,
                    "enabled": True
                },
                {
                    "type": "ssn",
                    "pattern": r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
                    "replacement": "[SSN]",
                    "description": "Social Security Numbers",
                    "priority": 1,
                    "enabled": True
                },
                {
                    "type": "credit_card",
                    "pattern": r"\b(?:\d[ -]*?){13,16}\b",
                    "replacement": "[CREDIT_CARD]",
                    "description": "Credit card numbers",
                    "priority": 1,
                    "enabled": True
                },
                {
                    "type": "address",
                    "pattern": r"\b\d+\s+[A-Za-z\s,]+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b",
                    "replacement": "[ADDRESS]",
                    "description": "Street addresses",
                    "priority": 3,
                    "enabled": True
                },
                {
                    "type": "name",
                    "pattern": r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b",
                    "replacement": "[NAME]",
                    "description": "Full names with titles",
                    "priority": 3,
                    "enabled": True
                },
                {
                    "type": "dob",
                    "pattern": r"\b\d{2}[-/]\d{2}[-/]\d{4}\b",
                    "replacement": "[DOB]",
                    "description": "Dates of birth",
                    "priority": 2,
                    "enabled": True
                },
                {
                    "type": "ip_address",
                    "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    "replacement": "[IP_ADDRESS]",
                    "description": "IP addresses",
                    "priority": 2,
                    "enabled": True
                },
                {
                    "type": "passport",
                    "pattern": r"\b[A-Z]\d{7}\b",
                    "replacement": "[PASSPORT]",
                    "description": "Passport numbers",
                    "priority": 1,
                    "enabled": True
                },
                {
                    "type": "bank_account",
                    "pattern": r"\b\d{8,12}\b",
                    "replacement": "[BANK_ACCOUNT]",
                    "description": "Bank account numbers",
                    "priority": 1,
                    "enabled": True
                }
            ],
            "sensitive_types": [
                "ssn",
                "credit_card",
                "bank_account",
                "passport"
            ]
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _load_default_patterns(self) -> None:
        """Load default patterns if config loading fails"""
        self.patterns = [
            MaskingPattern(
                type=PIIType.EMAIL,
                pattern=r"\b[\w.-]+@[\w.-]+\.\w+\b",
                replacement="[EMAIL]",
                description="Email addresses",
                priority=1
            ),
            MaskingPattern(
                type=PIIType.PHONE,
                pattern=r"\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b",
                replacement="[PHONE]",
                description="Phone numbers",
                priority=2
            )
        ]
        self.sensitive_types = {PIIType.EMAIL, PIIType.PHONE}
        
    def _compile_patterns(self) -> None:
        """Compile all enabled regex patterns"""
        self.compiled_patterns.clear()
        for pattern in sorted(self.patterns, key=lambda x: x.priority):
            if pattern.enabled:
                try:
                    self.compiled_patterns[pattern.type] = pattern.compile()
                except ValueError as e:
                    logger.error(f"Skipping pattern: {str(e)}")
                    
    def add_pattern(self, pattern: MaskingPattern) -> None:
        """Add a new masking pattern"""
        self.patterns.append(pattern)
        if pattern.enabled:
            self.compiled_patterns[pattern.type] = pattern.compile()
            
    def remove_pattern(self, pii_type: PIIType) -> None:
        """Remove a masking pattern"""
        self.patterns = [p for p in self.patterns if p.type != pii_type]
        self.compiled_patterns.pop(pii_type, None)
        
    def mask_pii(self, text: str, types: Optional[List[PIIType]] = None) -> str:
        """
        Mask PII in text with configurable pattern types
        
        Args:
            text: Text to mask
            types: Optional list of PII types to mask. If None, masks all types.
        
        Returns:
            Text with masked PII
        """
        if not text:
            return text
            
        # Reset masked count
        self.masked_count = {t: 0 for t in PIIType}
        
        # Create working copy
        masked_text = text
        
        # Apply patterns in priority order
        for pii_type, pattern in self.compiled_patterns.items():
            if types is None or pii_type in types:
                try:
                    # Count matches before masking
                    matches = len(pattern.findall(masked_text))
                    self.masked_count[pii_type] += matches
                    
                    # Apply masking
                    replacement = next(p.replacement for p in self.patterns if p.type == pii_type)
                    masked_text = pattern.sub(replacement, masked_text)
                    
                    # Log sensitive data detection
                    if matches > 0 and pii_type in self.sensitive_types:
                        logger.warning(f"Found {matches} instances of sensitive {pii_type.value}")
                        
                except Exception as e:
                    logger.error(f"Error masking {pii_type.value}: {str(e)}")
                    
        return masked_text
        
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about masked PII"""
        return {
            "total_masked": sum(self.masked_count.values()),
            **{t.value: count for t, count in self.masked_count.items() if count > 0}
        }
        
    def validate_pattern(self, pattern: str) -> bool:
        """Validate regex pattern"""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
            
# Legacy support
def mask_pii(text: str) -> str:
    """Legacy wrapper for backward compatibility"""
    masker = PIIMasker()
    return masker.mask_pii(text)
