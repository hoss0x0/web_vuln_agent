import asyncio
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any
import yaml
from pathlib import Path
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger
from chains.learning.pii_masker import PIIMasker

logger = setup_logger(__name__)

class SummaryType(Enum):
    """Types of vulnerability summaries"""
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    DETAILED = "detailed"
    BRIEF = "brief"
    MITIGATION = "mitigation"
    IMPACT = "impact"

class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Summary:
    """Structured summary of a security finding"""
    id: str
    type: SummaryType
    title: str
    description: str
    severity: Severity
    affected_components: List[str]
    impact_assessment: str
    mitigation_steps: List[str]
    metadata: Dict[str, Any]
    timestamp: str
    hash: str

    @classmethod
    def from_dict(cls, data: Dict) -> 'Summary':
        """Create Summary from dictionary"""
        return cls(
            id=data.get('id', ''),
            type=SummaryType(data.get('type', 'technical')),
            title=data.get('title', ''),
            description=data.get('description', ''),
            severity=Severity(data.get('severity', 'medium')),
            affected_components=data.get('affected_components', []),
            impact_assessment=data.get('impact_assessment', ''),
            mitigation_steps=data.get('mitigation_steps', []),
            metadata=data.get('metadata', {}),
            timestamp=data.get('timestamp', datetime.utcnow().isoformat()),
            hash=data.get('hash', '')
        )

class SummaryGenerator:
    """Enhanced summary generator with advanced features"""
    
    def __init__(self):
        self._load_config()
        self.pii_masker = PIIMasker()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def _load_config(self) -> None:
        """Load summary configuration"""
        try:
            config_path = Path("config/summary_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
                
        except Exception as e:
            logger.error(f"Failed to load summary config: {str(e)}")
            self._load_default_config()
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "summary_types": {
                "technical": {
                    "prompt_template": """Generate a detailed technical summary of the following vulnerability finding.
                    Focus on technical details, affected components, and specific mitigation steps.
                    
                    Finding: {finding}
                    
                    Include:
                    1. Technical description
                    2. Affected components
                    3. Impact assessment
                    4. Detailed mitigation steps
                    5. Technical recommendations""",
                    "max_length": 1000,
                    "include_code_snippets": True
                },
                "executive": {
                    "prompt_template": """Generate an executive summary of the following vulnerability finding.
                    Focus on business impact, risk level, and high-level mitigation strategy.
                    
                    Finding: {finding}
                    
                    Include:
                    1. Business impact
                    2. Risk assessment
                    3. High-level mitigation strategy
                    4. Resource requirements
                    5. Timeline recommendations""",
                    "max_length": 500,
                    "include_code_snippets": False
                }
            },
            "masking": {
                "enabled": True,
                "mask_types": ["email", "ip_address", "credit_card"]
            },
            "batch_processing": {
                "max_concurrent": 4,
                "chunk_size": 10
            }
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _load_default_config(self) -> None:
        """Load default configuration"""
        self.config = {
            "summary_types": {
                "technical": {
                    "prompt_template": "Summarize the following vulnerability finding in 10-15 sentences for a technical security report.\n\nFinding:\n{finding}",
                    "max_length": 1000,
                    "include_code_snippets": True
                }
            },
            "masking": {"enabled": True},
            "batch_processing": {"max_concurrent": 4}
        }
        
    def _generate_hash(self, finding: Dict) -> str:
        """Generate unique hash for finding"""
        content = f"{finding.get('title', '')}:{finding.get('description', '')}"
        return hashlib.sha256(content.encode()).hexdigest()
        
    async def _mask_sensitive_data(self, text: str) -> str:
        """Mask sensitive data in text"""
        if self.config["masking"]["enabled"]:
            return self.pii_masker.mask_pii(text)
        return text
        
    async def summarize_finding(
        self,
        finding: Dict,
        summary_type: SummaryType = SummaryType.TECHNICAL
    ) -> Summary:
        """
        Generate structured summary for a finding
        
        Args:
            finding: Finding to summarize
            summary_type: Type of summary to generate
            
        Returns:
            Structured summary
        """
        try:
            # Mask sensitive data if enabled
            masked_finding = await self._mask_sensitive_data(json.dumps(finding))
            
            # Get summary configuration
            summary_config = self.config["summary_types"][summary_type.value]
            prompt = summary_config["prompt_template"].format(finding=masked_finding)
            
            # Generate summary using RAG
            summary_text = await asyncio.to_thread(
                generate_response,
                prompt
            )
            
            # Extract structured information
            structured_data = await self._extract_structured_data(summary_text)
            
            # Create Summary object
            summary = Summary(
                id=finding.get("id", hashlib.sha256(summary_text.encode()).hexdigest()[:8]),
                type=summary_type,
                title=structured_data.get("title", ""),
                description=structured_data.get("description", ""),
                severity=Severity(finding.get("severity", "medium")),
                affected_components=structured_data.get("affected_components", []),
                impact_assessment=structured_data.get("impact_assessment", ""),
                mitigation_steps=structured_data.get("mitigation_steps", []),
                metadata={
                    "original_finding_id": finding.get("id", ""),
                    "summary_timestamp": datetime.utcnow().isoformat(),
                    "summary_type": summary_type.value,
                    "raw_summary": summary_text
                },
                timestamp=datetime.utcnow().isoformat(),
                hash=self._generate_hash(finding)
            )
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to generate summary: {str(e)}")
            raise
            
    async def _extract_structured_data(self, summary_text: str) -> Dict:
        """Extract structured data from summary text using RAG"""
        prompt = f"""Extract structured information from the following security finding summary:

Summary:
{summary_text}

Extract:
1. Title
2. Description
3. Affected components (as list)
4. Impact assessment
5. Mitigation steps (as list)
"""
        
        # Generate structured data using RAG
        structured_text = await asyncio.to_thread(
            generate_response,
            prompt
        )
        
        try:
            # Parse the structured text into a dictionary
            # This is a simplified parser - in practice you'd want more robust parsing
            lines = structured_text.split("\n")
            data = {}
            current_key = None
            current_list = []
            
            for line in lines:
                if line.startswith("Title:"):
                    data["title"] = line.replace("Title:", "").strip()
                elif line.startswith("Description:"):
                    data["description"] = line.replace("Description:", "").strip()
                elif line.startswith("Affected components:"):
                    current_key = "affected_components"
                    current_list = []
                elif line.startswith("Impact assessment:"):
                    if current_key:
                        data[current_key] = current_list
                    data["impact_assessment"] = line.replace("Impact assessment:", "").strip()
                    current_key = None
                elif line.startswith("Mitigation steps:"):
                    current_key = "mitigation_steps"
                    current_list = []
                elif line.strip().startswith("- ") and current_key:
                    current_list.append(line.strip().replace("- ", ""))
                    
            if current_key:
                data[current_key] = current_list
                
            return data
            
        except Exception as e:
            logger.error(f"Failed to extract structured data: {str(e)}")
            return {
                "title": "",
                "description": summary_text,
                "affected_components": [],
                "impact_assessment": "",
                "mitigation_steps": []
            }
            
    async def summarize_findings_batch(
        self,
        findings: List[Dict],
        summary_type: SummaryType = SummaryType.TECHNICAL
    ) -> List[Summary]:
        """
        Generate summaries for multiple findings concurrently
        
        Args:
            findings: List of findings to summarize
            summary_type: Type of summaries to generate
            
        Returns:
            List of structured summaries
        """
        try:
            # Process findings in chunks
            chunk_size = self.config["batch_processing"]["max_concurrent"]
            summaries = []
            
            for i in range(0, len(findings), chunk_size):
                chunk = findings[i:i + chunk_size]
                tasks = [
                    self.summarize_finding(finding, summary_type)
                    for finding in chunk
                ]
                chunk_summaries = await asyncio.gather(*tasks)
                summaries.extend(chunk_summaries)
                
            return summaries
            
        except Exception as e:
            logger.error(f"Failed to process findings batch: {str(e)}")
            raise

# Legacy support functions
async def summarize_finding(finding: Dict) -> str:
    """Legacy wrapper for backward compatibility"""
    generator = SummaryGenerator()
    summary = await generator.summarize_finding(finding)
    return summary.description

async def summarize_findings_batch(findings: List[Dict]) -> List[str]:
    """Legacy wrapper for backward compatibility"""
    generator = SummaryGenerator()
    summaries = await generator.summarize_findings_batch(findings)
    return [s.description for s in summaries]
