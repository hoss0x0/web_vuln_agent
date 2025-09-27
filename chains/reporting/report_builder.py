import json
import os
import re
from datetime import datetime
from collections import Counter
from typing import List, Dict, Optional, Union
from urllib.parse import urlparse

class ValidationError(Exception):
    """Custom exception for input validation errors"""
    pass

class ReportBuilder:
    """Enhanced report builder with support for JSON and Markdown formats"""
    
    SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
    REQUIRED_FINDING_FIELDS = ["severity", "category", "endpoint"]
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize report builder with configurable output directory"""
        self.output_dir = output_dir
        try:
            os.makedirs(output_dir, exist_ok=True)
        except PermissionError:
            raise PermissionError(f"Cannot create output directory: {output_dir}. Please check permissions.")
        except Exception as e:
            raise Exception(f"Error creating output directory: {str(e)}")
        
    def _generate_filename(self, prefix: str, ext: str) -> str:
        """Generate a unique timestamped filename"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.output_dir, f"{prefix}_{timestamp}.{ext}")
    
    def _validate_findings(self, findings: List[Dict]) -> None:
        """Validate the findings data structure"""
        if not isinstance(findings, list):
            raise ValidationError("Findings must be a list")
        
        if not findings:
            raise ValidationError("Findings list cannot be empty")
            
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise ValidationError(f"Finding {i} must be a dictionary")
                
            for field in self.REQUIRED_FINDING_FIELDS:
                if field not in finding:
                    raise ValidationError(f"Finding {i} missing required field: {field}")
                    
            if finding.get("severity") not in self.SEVERITY_LEVELS:
                raise ValidationError(
                    f"Finding {i} has invalid severity level. Must be one of: {', '.join(self.SEVERITY_LEVELS)}"
                )
    
    def _validate_target_url(self, target_url: str) -> None:
        """Validate the target URL"""
        if not isinstance(target_url, str):
            raise ValidationError("Target URL must be a string")
            
        if not target_url:
            raise ValidationError("Target URL cannot be empty")
            
        try:
            parsed = urlparse(target_url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValidationError("Invalid URL format")
        except Exception:
            raise ValidationError("Invalid URL format")
    
    def _analyze_findings(self, findings: List[Dict]) -> Dict:
        """Generate statistics and analysis of findings"""
        stats = {
            "total_findings": len(findings),
            "severity_counts": Counter(f.get("severity", "Unknown") for f in findings),
            "category_counts": Counter(f.get("category", "Unknown") for f in findings),
            "unique_endpoints": len(set(f.get("endpoint", "") for f in findings)),
            "top_affected_endpoints": Counter(f.get("endpoint", "") for f in findings).most_common(5)
        }
        return stats
    
    def build_report(self, findings: List[Dict], target_url: str, custom_path: Optional[str] = None) -> str:
        """
        Build an enhanced JSON report from attack findings
        
        Args:
            findings: List of finding dictionaries
            target_url: URL of the target system
            custom_path: Optional custom output path
            
        Returns:
            Path to the generated report file
            
        Raises:
            ValidationError: If the input data is invalid
            IOError: If there are issues writing the report
            Exception: For other unexpected errors
        """
        try:
            # Validate inputs
            self._validate_findings(findings)
            self._validate_target_url(target_url)
            
            # If custom path provided, validate directory exists
            if custom_path:
                os.makedirs(os.path.dirname(os.path.abspath(custom_path)), exist_ok=True)
            
            stats = self._analyze_findings(findings)
            
            report = {
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "summary_stats": stats,
                "findings": [
                    {
                        **finding,
                        "severity": finding.get("severity", "Unknown"),
                        "category": finding.get("category", "Unknown"),
                        "remediation": finding.get("remediation", "No remediation provided"),
                        "references": finding.get("references", [])
                    }
                    for finding in findings
                ]
            }
            
            output_path = custom_path or self._generate_filename("vuln_report", "json")
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            print(f"[✓] Enhanced JSON report saved to {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[!] Error generating JSON report: {str(e)}")
            raise

    def build_markdown_report(self, findings: List[Dict], target_url: str, custom_path: Optional[str] = None) -> str:
        """
        Build an enhanced Markdown report with better formatting and statistics
        
        Args:
            findings: List of finding dictionaries
            target_url: URL of the target system
            custom_path: Optional custom output path
            
        Returns:
            Path to the generated report file
            
        Raises:
            ValidationError: If the input data is invalid
            ImportError: If required modules are not available
            IOError: If there are issues writing the report
            Exception: For other unexpected errors
        """
        try:
            # Validate inputs
            self._validate_findings(findings)
            self._validate_target_url(target_url)
            
            # If custom path provided, validate directory exists
            if custom_path:
                os.makedirs(os.path.dirname(os.path.abspath(custom_path)), exist_ok=True)
            
            try:
                from chains.learning.summary_generation import summarize_findings_batch
            except ImportError:
                raise ImportError("Could not import summary_generation module. Please ensure it is installed.")
            
            summaries = summarize_findings_batch(findings)
            stats = self._analyze_findings(findings)
            
            # Build the report sections
            sections = []
            
            # Header
            sections.append(f"# Vulnerability Assessment Report\n")
            sections.append("## Executive Summary\n")
            sections.append(f"**Target:** {target_url}")
            sections.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
            sections.append(f"**Total Findings:** {stats['total_findings']}\n")
            
            # Statistics Section
            sections.append("## Statistics\n")
            sections.append("### Severity Distribution\n")
            sections.append("| Severity | Count |")
            sections.append("|----------|-------|")
            for severity in self.SEVERITY_LEVELS:
                count = stats['severity_counts'].get(severity, 0)
                sections.append(f"| {severity} | {count} |")
            
            sections.append("\n### Category Distribution\n")
            sections.append("| Category | Count |")
            sections.append("|----------|-------|")
            for category, count in stats['category_counts'].most_common():
                sections.append(f"| {category} | {count} |")
            
            # Detailed Findings
            sections.append("\n## Detailed Findings\n")
            for i, (finding, summary) in enumerate(zip(findings, summaries), 1):
                severity = finding.get("severity", "Unknown")
                category = finding.get("category", "Unknown")
                
                sections.append(f"### Finding {i}: {category}\n")
                sections.append(f"**Severity:** {severity}")
                sections.append(f"**Category:** {category}")
                sections.append(f"**Endpoint:** {finding.get('endpoint', 'N/A')}\n")
                sections.append("#### Description")
                sections.append(summary)
                
                if remediation := finding.get("remediation"):
                    sections.append("\n#### Remediation")
                    sections.append(remediation)
                
                if references := finding.get("references"):
                    sections.append("\n#### References")
                    sections.extend([f"- {ref}" for ref in references])
                
                sections.append("\n---\n")
            
            output_path = custom_path or self._generate_filename("vuln_report", "md")
            
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sections))
                
            print(f"[✓] Enhanced Markdown report saved to {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[!] Error generating Markdown report: {str(e)}")
            raise
