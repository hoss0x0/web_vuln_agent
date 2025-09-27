import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
import yaml
from pathlib import Path
import re
from concurrent.futures import ThreadPoolExecutor
import asyncio
import hashlib

from rag_layer.retriever import retrieve_chunks
from utils.logger import setup_logger
from chains.payloads.payload_metadata import PayloadAnalyzer

logger = setup_logger(__name__)

class VulnerabilityCategory(Enum):
    """Categories of vulnerabilities"""
    INJECTION = "injection"
    XSS = "xss"
    SQLI = "sql_injection"
    CMDI = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    FILE = "file_inclusion"
    DESERIALIZATION = "deserialization"
    TRAVERSAL = "path_traversal"
    GENERIC = "generic"

class PayloadComplexity(Enum):
    """Complexity levels for payloads"""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ADVANCED = "advanced"

@dataclass
class PayloadMatch:
    """Structured payload match result"""
    payload: str
    source: str
    category: VulnerabilityCategory
    complexity: PayloadComplexity
    tags: List[str]
    effectiveness_score: float
    retrieval_score: float
    metadata: Dict[str, Any]
    timestamp: str
    hash: str = field(init=False)

    def __post_init__(self):
        self.hash = hashlib.sha256(self.payload.encode()).hexdigest()

class PayloadRetriever:
    """Enhanced payload retriever with advanced features"""
    
    def __init__(self):
        self._load_config()
        self.analyzer = PayloadAnalyzer()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._initialize_patterns()
        
    def _load_config(self) -> None:
        """Load retriever configuration"""
        try:
            config_path = Path("config/payload_analyzer.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
                
        except Exception as e:
            logger.error(f"Failed to load retriever config: {str(e)}")
            self._load_default_config()
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "retrieval": {
                "max_results": 50,
                "min_score": 0.5,
                "deduplication": True,
                "combine_similar": True
            },
            "filtering": {
                "min_length": 5,
                "max_length": 1000,
                "required_patterns": {
                    "xss": [r"<[^>]+>", r"javascript:", r"on\w+="],
                    "sqli": [r"(?i)(?:union|select|from|where)", r"(?i)(?:--|\#|\/\*)", r"\d+\s*=\s*\d+"],
                    "cmdi": [r"[;&|`]", r"\$\(", r"\b(?:cat|curl|wget)\b"],
                },
                "excluded_patterns": [
                    r"rm\s+-rf",
                    r"drop\s+database",
                    r"format\s+[cf]:"
                ]
            },
            "scoring": {
                "pattern_weight": 0.4,
                "complexity_weight": 0.3,
                "retrieval_weight": 0.3,
                "length_penalty": 0.1
            },
            "categories": {
                "injection": ["sql", "command", "code", "template"],
                "xss": ["reflected", "stored", "dom"],
                "file": ["include", "upload", "download"]
            }
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _load_default_config(self) -> None:
        """Load default configuration"""
        self.config = {
            "retrieval": {
                "max_results": 20,
                "min_score": 0.5
            },
            "filtering": {
                "required_patterns": {}
            }
        }
        
    def _initialize_patterns(self) -> None:
        """Initialize regex patterns"""
        self.patterns = {
            VulnerabilityCategory.XSS: [
                re.compile(pattern) 
                for pattern in self.config["filtering"]["required_patterns"].get("xss", [])
            ],
            VulnerabilityCategory.SQLI: [
                re.compile(pattern)
                for pattern in self.config["filtering"]["required_patterns"].get("sqli", [])
            ],
            VulnerabilityCategory.CMDI: [
                re.compile(pattern)
                for pattern in self.config["filtering"]["required_patterns"].get("cmdi", [])
            ]
        }
        
        self.excluded_patterns = [
            re.compile(pattern)
            for pattern in self.config["filtering"].get("excluded_patterns", [])
        ]
        
    def _determine_category(self, payload: str) -> VulnerabilityCategory:
        """Determine vulnerability category from payload"""
        for category, patterns in self.patterns.items():
            if any(pattern.search(payload) for pattern in patterns):
                return category
        return VulnerabilityCategory.GENERIC
        
    def _determine_complexity(self, payload: str) -> PayloadComplexity:
        """Determine payload complexity"""
        # Base score on length, special characters, and patterns
        score = 0
        
        # Length complexity
        length = len(payload)
        if length < 20:
            score += 1
        elif length < 50:
            score += 2
        else:
            score += 3
            
        # Special character complexity
        special_chars = set("!@#$%^&*(){}[]<>?+")
        special_count = sum(1 for c in payload if c in special_chars)
        score += min(3, special_count // 2)
        
        # Pattern complexity
        if any(pattern.search(payload) for pattern in self.patterns.get(VulnerabilityCategory.XSS, [])):
            score += 1
        if any(pattern.search(payload) for pattern in self.patterns.get(VulnerabilityCategory.SQLI, [])):
            score += 2
            
        # Determine complexity level
        if score <= 2:
            return PayloadComplexity.SIMPLE
        elif score <= 4:
            return PayloadComplexity.MODERATE
        elif score <= 6:
            return PayloadComplexity.COMPLEX
        else:
            return PayloadComplexity.ADVANCED
            
    def _calculate_effectiveness(self, payload: str, category: VulnerabilityCategory) -> float:
        """Calculate payload effectiveness score"""
        score = 1.0
        
        # Pattern match score
        if category in self.patterns:
            pattern_matches = sum(1 for p in self.patterns[category] if p.search(payload))
            score *= 0.4 + (0.6 * pattern_matches / len(self.patterns[category]))
            
        # Length penalty
        length = len(payload)
        if length > 500:
            score *= 0.8
        elif length > 1000:
            score *= 0.6
            
        # Complexity bonus
        complexity = self._determine_complexity(payload)
        if complexity == PayloadComplexity.ADVANCED:
            score *= 1.2
        elif complexity == PayloadComplexity.COMPLEX:
            score *= 1.1
            
        return round(min(1.0, score), 2)
        
    def _extract_tags(self, payload: str, category: VulnerabilityCategory) -> List[str]:
        """Extract relevant tags from payload"""
        tags = [category.value]
        
        # Add technique tags
        if "<script" in payload.lower():
            tags.append("script-injection")
        if "union" in payload.lower():
            tags.append("union-based")
        if "/*" in payload or "--" in payload:
            tags.append("comment-based")
        if "alert(" in payload:
            tags.append("proof-of-concept")
            
        # Add target tags
        if "cookie" in payload.lower():
            tags.append("cookie-manipulation")
        if "database" in payload.lower():
            tags.append("database-targeting")
        if "file" in payload.lower():
            tags.append("file-operation")
            
        return list(set(tags))
        
    async def get_payloads(
        self,
        vulnerability_type: str,
        injection_type: str,
        top_k: int = 5,
        min_score: float = 0.5,
        complexity: Optional[PayloadComplexity] = None,
        tags: Optional[List[str]] = None
    ) -> List[PayloadMatch]:
        """
        Retrieve and analyze relevant payloads
        
        Args:
            vulnerability_type: Type of vulnerability to target
            injection_type: Type of injection method
            top_k: Maximum number of results
            min_score: Minimum effectiveness score
            complexity: Filter by complexity level
            tags: Filter by required tags
            
        Returns:
            List of structured payload matches
        """
        try:
            # Build enhanced query
            query = self._build_query(vulnerability_type, injection_type)
            
            # Retrieve chunks with context
            chunks = await self._retrieve_chunks(query, top_k * 2)  # Get extra for filtering
            
            # Process chunks in parallel
            tasks = [
                self._process_chunk(chunk, vulnerability_type)
                for chunk in chunks
            ]
            
            matches = []
            for results in await asyncio.gather(*tasks):
                matches.extend(results)
                
            # Filter and sort results
            matches = self._filter_results(
                matches,
                min_score=min_score,
                complexity=complexity,
                tags=tags
            )
            
            # Sort by effectiveness score
            matches.sort(key=lambda x: x.effectiveness_score, reverse=True)
            
            return matches[:top_k]
            
        except Exception as e:
            logger.error(f"Failed to retrieve payloads: {str(e)}")
            return []
            
    def _build_query(self, vuln_type: str, injection_type: str) -> str:
        """Build enhanced retrieval query"""
        category_terms = self.config["categories"].get(vuln_type.lower(), [])
        
        query = f"""
        Retrieve payloads for {vuln_type} using {injection_type} injection.
        Consider variations and techniques like:
        - {', '.join(category_terms)}
        Focus on effective and well-tested payloads.
        """
        
        return query.strip()
        
    async def _retrieve_chunks(self, query: str, top_k: int) -> List[Dict]:
        """Retrieve chunks with error handling"""
        try:
            return await self._run_in_thread(retrieve_chunks, query, top_k=top_k)
        except Exception as e:
            logger.error(f"Chunk retrieval failed: {str(e)}")
            return []
            
    async def _process_chunk(
        self,
        chunk: Dict,
        vuln_type: str
    ) -> List[PayloadMatch]:
        """Process a single chunk"""
        matches = []
        try:
            lines = chunk["content"].splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Skip excluded patterns
                if any(pattern.search(line) for pattern in self.excluded_patterns):
                    continue
                    
                # Analyze payload
                category = self._determine_category(line)
                complexity = self._determine_complexity(line)
                effectiveness = self._calculate_effectiveness(line, category)
                tags = self._extract_tags(line, category)
                
                if effectiveness >= self.config["retrieval"]["min_score"]:
                    matches.append(PayloadMatch(
                        payload=line,
                        source=chunk["metadata"]["source_file"],
                        category=category,
                        complexity=complexity,
                        tags=tags,
                        effectiveness_score=effectiveness,
                        retrieval_score=chunk.get("score", 0.0),
                        metadata={
                            "chunk_id": chunk.get("id"),
                            "original_query": chunk.get("query"),
                            "vulnerability_type": vuln_type
                        },
                        timestamp=datetime.utcnow().isoformat()
                    ))
                    
        except Exception as e:
            logger.error(f"Failed to process chunk: {str(e)}")
            
        return matches
        
    def _filter_results(
        self,
        matches: List[PayloadMatch],
        min_score: float,
        complexity: Optional[PayloadComplexity] = None,
        tags: Optional[List[str]] = None
    ) -> List[PayloadMatch]:
        """Filter and deduplicate results"""
        filtered = []
        seen_hashes = set()
        
        for match in matches:
            # Skip if below minimum score
            if match.effectiveness_score < min_score:
                continue
                
            # Skip if wrong complexity
            if complexity and match.complexity != complexity:
                continue
                
            # Skip if missing required tags
            if tags and not all(tag in match.tags for tag in tags):
                continue
                
            # Skip duplicates
            if match.hash in seen_hashes:
                continue
                
            filtered.append(match)
            seen_hashes.add(match.hash)
            
        return filtered
        
    async def _run_in_thread(self, func, *args, **kwargs):
        """Run function in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, func, *args, **kwargs)

# Legacy support
async def get_payloads(
    vulnerability_type: str,
    injection_type: str,
    top_k: int = 5
) -> List[Dict]:
    """Legacy wrapper for backward compatibility"""
    retriever = PayloadRetriever()
    matches = await retriever.get_payloads(vulnerability_type, injection_type, top_k)
    return [{"payload": m.payload, "source": m.source} for m in matches]
