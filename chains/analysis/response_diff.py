import difflib
import re
import logging
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from bs4 import BeautifulSoup
from collections import defaultdict
import json
from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class DiffResult:
    """Container for difference analysis results"""
    raw_diff: str
    html_diff: Optional[str]
    structural_changes: Dict[str, List[str]]
    similarity_score: float
    content_changes: Dict[str, int]
    sensitive_data_exposed: List[str]
    analysis: List[str]

class ResponseDiffAnalyzer:
    """Enhanced response difference analyzer with HTML awareness"""

    def __init__(self):
        self.sensitive_patterns = [
            r"(?i)password|secret|token|key|auth|pwd|credential",
            r"(?i)ssn|social.*security",
            r"(?i)credit.*card|card.*number",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",  # SSN pattern
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"  # Credit card pattern
        ]
        
        self.html_focus_elements = {
            "script": "JavaScript code",
            "iframe": "Embedded frames",
            "form": "Form elements",
            "input": "Input fields",
            "link": "Link elements",
            "meta": "Meta tags",
            "style": "Style elements"
        }

    def analyze_responses(
        self, 
        original: str, 
        injected: str,
        context: Optional[Dict] = None
    ) -> DiffResult:
        """
        Perform comprehensive difference analysis between original and injected responses
        
        Args:
            original: Original response content
            injected: Modified response content
            context: Additional context about the responses
            
        Returns:
            DiffResult containing detailed analysis
        """
        try:
            # Calculate raw text diff
            raw_diff = self._calculate_raw_diff(original, injected)
            
            # Calculate similarity score
            similarity = self._calculate_similarity(original, injected)
            
            # Initialize results
            results = {
                "raw_diff": raw_diff,
                "html_diff": None,
                "structural_changes": {},
                "similarity_score": similarity,
                "content_changes": self._analyze_content_changes(original, injected),
                "sensitive_data_exposed": [],
                "analysis": []
            }
            
            # Perform HTML-specific analysis if content appears to be HTML
            if self._is_html_content(original) or self._is_html_content(injected):
                html_analysis = self._analyze_html_differences(original, injected)
                results.update(html_analysis)
            
            # Check for sensitive data exposure
            results["sensitive_data_exposed"] = self._check_sensitive_data(
                original, injected
            )
            
            # Generate analysis summary
            results["analysis"] = self._generate_analysis(results)
            
            return DiffResult(**results)
            
        except Exception as e:
            logger.error(f"Error analyzing responses: {str(e)}")
            return DiffResult(
                raw_diff="Error in analysis",
                html_diff=None,
                structural_changes={},
                similarity_score=0.0,
                content_changes={},
                sensitive_data_exposed=[],
                analysis=[f"Error during analysis: {str(e)}"]
            )

    def _calculate_raw_diff(self, original: str, injected: str) -> str:
        """Calculate raw text difference"""
        try:
            diff = difflib.unified_diff(
                original.splitlines(),
                injected.splitlines(),
                fromfile="original",
                tofile="injected",
                lineterm=""
            )
            return "\n".join(diff)
        except Exception as e:
            logger.error(f"Error calculating raw diff: {str(e)}")
            return "Error calculating differences"

    def _calculate_similarity(self, original: str, injected: str) -> float:
        """Calculate similarity ratio between responses"""
        try:
            matcher = difflib.SequenceMatcher(None, original, injected)
            return matcher.ratio()
        except Exception as e:
            logger.error(f"Error calculating similarity: {str(e)}")
            return 0.0

    def _is_html_content(self, content: str) -> bool:
        """Determine if content is HTML"""
        try:
            return bool(re.search(r"<!DOCTYPE html>|<html|<body|<head", content, re.I))
        except Exception:
            return False

    def _analyze_html_differences(self, original: str, injected: str) -> Dict:
        """Analyze differences in HTML structure and content"""
        try:
            # Parse HTML
            original_soup = BeautifulSoup(original, 'html.parser')
            injected_soup = BeautifulSoup(injected, 'html.parser')
            
            structural_changes = defaultdict(list)
            
            # Compare focus elements
            for element, description in self.html_focus_elements.items():
                original_elements = original_soup.find_all(element)
                injected_elements = injected_soup.find_all(element)
                
                # Check for added/removed elements
                if len(original_elements) != len(injected_elements):
                    structural_changes[element].append(
                        f"Changed number of {description}: {len(original_elements)} → {len(injected_elements)}"
                    )
                
                # Check for modified elements
                for orig, inj in zip(original_elements, injected_elements):
                    if str(orig) != str(inj):
                        structural_changes[element].append(
                            f"Modified {description}: {str(orig)[:50]} → {str(inj)[:50]}"
                        )
            
            # Generate HTML diff with highlighting
            html_diff = self._generate_html_diff(original_soup, injected_soup)
            
            return {
                "html_diff": html_diff,
                "structural_changes": dict(structural_changes)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing HTML differences: {str(e)}")
            return {
                "html_diff": None,
                "structural_changes": {}
            }

    def _generate_html_diff(self, original_soup: BeautifulSoup, injected_soup: BeautifulSoup) -> str:
        """Generate HTML diff with highlighting"""
        try:
            # Convert to pretty-printed HTML
            original_html = original_soup.prettify()
            injected_html = injected_soup.prettify()
            
            # Generate diff with HTML highlighting
            diff = difflib.HtmlDiff()
            return diff.make_file(
                original_html.splitlines(),
                injected_html.splitlines(),
                "Original",
                "Modified"
            )
        except Exception as e:
            logger.error(f"Error generating HTML diff: {str(e)}")
            return ""

    def _analyze_content_changes(self, original: str, injected: str) -> Dict[str, int]:
        """Analyze content changes statistics"""
        return {
            "total_lines": len(injected.splitlines()),
            "changed_lines": sum(1 for line in difflib.unified_diff(
                original.splitlines(), injected.splitlines()
            )),
            "content_length_diff": len(injected) - len(original)
        }

    def _check_sensitive_data(self, original: str, injected: str) -> List[str]:
        """Check for exposed sensitive data in the differences"""
        exposed_data = []
        
        try:
            # Get only the added content
            added_content = "\n".join(
                line[1:] for line in difflib.unified_diff(
                    original.splitlines(),
                    injected.splitlines()
                ) if line.startswith("+")
            )
            
            # Check for sensitive patterns
            for pattern in self.sensitive_patterns:
                matches = re.finditer(pattern, added_content, re.I)
                for match in matches:
                    exposed_data.append({
                        "type": pattern.split("|")[0].replace("(?i)", ""),
                        "pattern": pattern,
                        "sample": match.group()[:20] + "..."
                    })
                    
            return exposed_data
            
        except Exception as e:
            logger.error(f"Error checking sensitive data: {str(e)}")
            return []

    def _generate_analysis(self, results: Dict) -> List[str]:
        """Generate detailed analysis summary"""
        analysis = []
        
        try:
            # Overall similarity
            analysis.append(f"Similarity score: {results['similarity_score']:.2%}")
            
            # Content changes
            changes = results["content_changes"]
            analysis.append(f"Changed {changes['changed_lines']} of {changes['total_lines']} lines")
            analysis.append(f"Content length difference: {changes['content_length_diff']} characters")
            
            # Structural changes if HTML
            if results["structural_changes"]:
                analysis.append("\nStructural changes:")
                for element, changes in results["structural_changes"].items():
                    for change in changes:
                        analysis.append(f"- {change}")
            
            # Sensitive data exposure
            if results["sensitive_data_exposed"]:
                analysis.append("\nPotential sensitive data exposure:")
                for data in results["sensitive_data_exposed"]:
                    analysis.append(f"- {data['type']}: {data['sample']}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error generating analysis: {str(e)}")
            return ["Error generating analysis"]

def diff_responses(original: str, injected: str) -> str:
    """Legacy wrapper for backward compatibility"""
    analyzer = ResponseDiffAnalyzer()
    result = analyzer.analyze_responses(original, injected)
    return result.raw_diff

def calculate_response_similarity(original: str, injected: str) -> float:
    """Calculate similarity between responses"""
    analyzer = ResponseDiffAnalyzer()
    return analyzer._calculate_similarity(original, injected)
