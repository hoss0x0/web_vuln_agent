import json
import logging
import re
import base64
import hashlib
import random
import urllib.parse
import html
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import asyncio

from rag_layer.rag_chain import generate_response
from utils.logger import setup_logger
from chains.learning.pii_masker import PIIMasker
from chains.payloads.payload_metadata import PayloadAnalyzer, PayloadMetadata

logger = setup_logger(__name__)

class MutationType(Enum):
    """Types of payload mutations"""
    ENCODING = "encoding"
    CASE = "case"
    WHITESPACE = "whitespace"
    CONCATENATION = "concatenation"
    ALTERNATIVE = "alternative"
    COMMENTS = "comments"
    CHARSET = "charset"
    PROTOCOL = "protocol"
    STRUCTURE = "structure"
    LOGIC = "logic"

@dataclass
class MutationResult:
    """Result of a payload mutation"""
    original_payload: str
    mutated_payload: str
    mutation_type: MutationType
    success_probability: float
    complexity: int
    mutation_description: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class PayloadMutator:
    """Enhanced payload mutator with advanced mutation strategies"""
    
    def __init__(self):
        self._load_config()
        self.analyzer = PayloadAnalyzer()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._initialize_mutation_functions()
        
    def _load_config(self) -> None:
        """Load mutator configuration"""
        try:
            config_path = Path("config/mutation_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
                
        except Exception as e:
            logger.error(f"Failed to load mutator config: {str(e)}")
            self._load_default_config()
            
    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "mutations": {
                "encoding": {
                    "enabled": True,
                    "max_nested": 3,
                    "types": ["base64", "url", "html", "unicode", "hex"]
                },
                "case": {
                    "enabled": True,
                    "random_ratio": 0.5
                },
                "whitespace": {
                    "enabled": True,
                    "max_spaces": 5,
                    "use_tabs": True
                },
                "concatenation": {
                    "enabled": True,
                    "operators": ["+", ".", "||", "concat"]
                },
                "comments": {
                    "enabled": True,
                    "inline": True,
                    "multiline": True
                }
            },
            "strategy": {
                "max_mutations": 10,
                "combine_mutations": True,
                "preserve_semantics": True,
                "complexity_limit": 5
            },
            "llm": {
                "enabled": True,
                "temperature": 0.7,
                "max_tokens": 500
            }
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f)
            
    def _load_default_config(self) -> None:
        """Load default configuration"""
        self.config = {
            "mutations": {
                "encoding": {"enabled": True},
                "case": {"enabled": True},
                "whitespace": {"enabled": True}
            },
            "strategy": {"max_mutations": 5}
        }
        
    def _initialize_mutation_functions(self) -> None:
        """Initialize mutation function mapping"""
        self.mutation_functions = {
            MutationType.ENCODING: self._mutate_encoding,
            MutationType.CASE: self._mutate_case,
            MutationType.WHITESPACE: self._mutate_whitespace,
            MutationType.CONCATENATION: self._mutate_concatenation,
            MutationType.COMMENTS: self._mutate_comments,
            MutationType.CHARSET: self._mutate_charset,
            MutationType.PROTOCOL: self._mutate_protocol,
            MutationType.STRUCTURE: self._mutate_structure,
            MutationType.LOGIC: self._mutate_logic
        }
        
    def _mutate_encoding(self, payload: str) -> List[str]:
        """Apply encoding mutations"""
        mutations = []
        encoding_config = self.config["mutations"]["encoding"]
        
        if encoding_config["enabled"]:
            # Base64 encoding
            mutations.append(base64.b64encode(payload.encode()).decode())
            
            # URL encoding
            mutations.append(urllib.parse.quote(payload))
            
            # HTML encoding
            mutations.append(html.escape(payload))
            
            # Unicode encoding
            mutations.append(payload.encode('unicode_escape').decode())
            
            # Hex encoding
            mutations.append(''.join([f'\\x{ord(c):02x}' for c in payload]))
            
            # Nested encodings (if configured)
            if encoding_config.get("max_nested", 0) > 1:
                nested = urllib.parse.quote(base64.b64encode(payload.encode()).decode())
                mutations.append(nested)
                
        return mutations
        
    def _mutate_case(self, payload: str) -> List[str]:
        """Apply case mutations"""
        mutations = []
        case_config = self.config["mutations"]["case"]
        
        if case_config["enabled"]:
            # Random case
            mutations.append(''.join(c.upper() if random.random() < case_config["random_ratio"] else c.lower() for c in payload))
            
            # Alternating case
            mutations.append(''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
            
            # Camel case words
            mutations.append(' '.join(word.capitalize() for word in payload.split()))
            
        return mutations
        
    def _mutate_whitespace(self, payload: str) -> List[str]:
        """Apply whitespace mutations"""
        mutations = []
        ws_config = self.config["mutations"]["whitespace"]
        
        if ws_config["enabled"]:
            # Random spaces
            max_spaces = ws_config["max_spaces"]
            mutations.append(re.sub(r'\s+', ' ' * random.randint(1, max_spaces), payload))
            
            # Tab replacement
            if ws_config["use_tabs"]:
                mutations.append(re.sub(r'\s+', '\t', payload))
                
            # Line breaks
            mutations.append(re.sub(r'\s+', '\n', payload))
            
        return mutations
        
    def _mutate_concatenation(self, payload: str) -> List[str]:
        """Apply string concatenation mutations"""
        mutations = []
        concat_config = self.config["mutations"]["concatenation"]
        
        if concat_config["enabled"]:
            operators = concat_config["operators"]
            
            for op in operators:
                # Split into parts
                parts = [c for c in payload]
                if op in ["+", "."]:
                    mutations.append(f"'{op}'".join(parts))
                elif op == "||":
                    mutations.append(f"'{op}'".join(parts))
                elif op == "concat":
                    mutations.append(f"concat({','.join(repr(p) for p in parts)})")
                    
        return mutations
        
    def _mutate_comments(self, payload: str) -> List[str]:
        """Apply comment injection mutations"""
        mutations = []
        comment_config = self.config["mutations"]["comments"]
        
        if comment_config["enabled"]:
            if comment_config["inline"]:
                # Inline comments between characters
                chars = list(payload)
                mutations.append(''.join(f"{c}/**/" for c in chars))
                
            if comment_config["multiline"]:
                # Wrapping multiline comments
                mutations.append(f"/*{random.randint(1000,9999)}*/{payload}/*{random.randint(1000,9999)}*/")
                
        return mutations
        
    def _mutate_charset(self, payload: str) -> List[str]:
        """Apply charset-based mutations"""
        mutations = []
        
        # Unicode homoglyphs
        homoglyphs = {
            'a': 'а', 'e': 'е', 'i': 'і', 'o': 'о', 'p': 'р',
            's': 'ѕ', 'c': 'с', 'B': 'В', 'H': 'Н', 'M': 'М'
        }
        
        # Replace with similar-looking characters
        mutated = ''.join(homoglyphs.get(c, c) for c in payload)
        if mutated != payload:
            mutations.append(mutated)
            
        return mutations
        
    def _mutate_protocol(self, payload: str) -> List[str]:
        """Apply protocol-based mutations"""
        mutations = []
        
        # Protocol variations
        if payload.startswith(('http://', 'https://')):
            mutations.extend([
                payload.replace('http://', 'hTtP://'),
                payload.replace('https://', 'hTtPs://'),
                payload.replace('://', '：//')  # Unicode colon
            ])
            
        return mutations
        
    def _mutate_structure(self, payload: str) -> List[str]:
        """Apply structural mutations"""
        mutations = []
        
        # Tag structure mutations for XSS
        if '<' in payload and '>' in payload:
            mutations.extend([
                payload.replace('<', '<%00'),
                payload.replace('>', '%00>'),
                payload.replace('<', '<%0d%0a')
            ])
            
        # SQL structure mutations
        if any(kw in payload.lower() for kw in ['select', 'union', 'from']):
            mutations.extend([
                payload.replace(' ', '/**/')
            ])
            
        return mutations
        
    def _mutate_logic(self, payload: str) -> List[str]:
        """Apply logic-based mutations"""
        mutations = []
        
        # Boolean logic mutations
        if '=' in payload:
            mutations.extend([
                payload.replace('=', '<>0^0='),
                payload.replace('=', 'like'),
                payload.replace('=', 'in()')
            ])
            
        return mutations
        
    async def mutate_payload(
        self,
        payload: str,
        context: Dict[str, Any],
        max_mutations: Optional[int] = None
    ) -> List[MutationResult]:
        """
        Generate mutations of a payload with advanced strategies
        
        Args:
            payload: Original payload to mutate
            context: Context information for mutation
            max_mutations: Maximum number of mutations to generate
            
        Returns:
            List of mutation results
        """
        try:
            mutations = []
            max_count = max_mutations or self.config["strategy"]["max_mutations"]
            
            # Get payload metadata for smart mutations
            metadata = await self.analyzer.analyze_payload(payload)
            
            # Apply pattern-based mutations
            for mutation_type, mutation_func in self.mutation_functions.items():
                if len(mutations) >= max_count:
                    break
                    
                try:
                    new_mutations = mutation_func(payload)
                    for mutated in new_mutations:
                        if len(mutations) >= max_count:
                            break
                            
                        mutations.append(MutationResult(
                            original_payload=payload,
                            mutated_payload=mutated,
                            mutation_type=mutation_type,
                            success_probability=self._estimate_success_probability(mutated, context),
                            complexity=self._calculate_complexity(mutated),
                            mutation_description=self._describe_mutation(payload, mutated, mutation_type),
                            timestamp=datetime.utcnow().isoformat(),
                            metadata={
                                "original_metadata": asdict(metadata),
                                "mutation_context": context
                            }
                        ))
                        
                except Exception as e:
                    logger.error(f"Failed to apply {mutation_type} mutation: {str(e)}")
                    
            # Apply LLM-based mutations if enabled
            if self.config["llm"]["enabled"] and len(mutations) < max_count:
                llm_mutations = await self._generate_llm_mutations(payload, context, metadata, max_count - len(mutations))
                mutations.extend(llm_mutations)
                
            # Sort by success probability
            mutations.sort(key=lambda x: x.success_probability, reverse=True)
            
            return mutations[:max_count]
            
        except Exception as e:
            logger.error(f"Failed to generate mutations: {str(e)}")
            return [MutationResult(
                original_payload=payload,
                mutated_payload=payload,
                mutation_type=MutationType.ENCODING,
                success_probability=1.0,
                complexity=0,
                mutation_description="Failed to generate mutations",
                timestamp=datetime.utcnow().isoformat()
            )]
            
    def _estimate_success_probability(self, payload: str, context: Dict) -> float:
        """Estimate probability of mutation success"""
        # Basic heuristics for success probability
        probability = 1.0
        
        # Complexity penalty
        complexity = self._calculate_complexity(payload)
        probability *= max(0.1, 1 - (complexity / 10))
        
        # Length penalty
        length_ratio = len(payload) / len(context.get("original_payload", payload))
        probability *= max(0.1, 1 - (length_ratio - 1) / 2)
        
        # Context-based adjustments
        if context.get("waf_detected"):
            probability *= 0.8
        
        return round(probability, 2)
        
    def _calculate_complexity(self, payload: str) -> int:
        """Calculate mutation complexity score"""
        complexity = 0
        
        # Encoding complexity
        complexity += sum(1 for e in ['%', '\\x', '\\u'] if e in payload)
        
        # Structure complexity
        complexity += payload.count('<') + payload.count('>')
        complexity += payload.count('/*') + payload.count('*/')
        
        # Logic complexity
        complexity += sum(1 for op in ['AND', 'OR', 'NOT', '||', '&&'] if op in payload.upper())
        
        return min(10, complexity)
        
    def _describe_mutation(self, original: str, mutated: str, mutation_type: MutationType) -> str:
        """Generate human-readable mutation description"""
        changes = []
        
        if mutation_type == MutationType.ENCODING:
            encodings = set()
            if '%' in mutated:
                encodings.add("URL")
            if '\\x' in mutated:
                encodings.add("hex")
            if '\\u' in mutated:
                encodings.add("unicode")
            if all(c in base64.b64encode(b'').decode() for c in mutated):
                encodings.add("base64")
            
            if encodings:
                changes.append(f"Applied {', '.join(encodings)} encoding")
                
        elif mutation_type == MutationType.CASE:
            if original.lower() != mutated.lower():
                changes.append("Modified character case")
                
        elif mutation_type == MutationType.WHITESPACE:
            if len(mutated) - len(mutated.strip()) > len(original) - len(original.strip()):
                changes.append("Added whitespace variation")
                
        elif mutation_type == MutationType.COMMENTS:
            if '/*' in mutated or '*/' in mutated:
                changes.append("Injected comments")
                
        return "; ".join(changes) or f"Applied {mutation_type.value} mutation"
        
    async def _generate_llm_mutations(
        self,
        payload: str,
        context: Dict,
        metadata: PayloadMetadata,
        count: int
    ) -> List[MutationResult]:
        """Generate mutations using LLM"""
        query = f"""Generate {count} mutations of the following payload to improve evasion or impact.

Original Payload:
{payload}

Vulnerability Type: {metadata.vulnerability_type.value}
Current Encodings: {[e.value for e in metadata.encodings]}
Evasion Techniques: {[e.value for e in metadata.evasion_techniques]}

Context:
{json.dumps(context, indent=2)}

Return a JSON list of objects with these fields:
1. mutated_payload: The mutated version
2. mutation_type: The primary type of mutation applied
3. description: Brief description of the changes
4. success_probability: Estimated success probability (0-1)
5. complexity: Estimated complexity score (0-10)
"""
        
        try:
            result = await self._analyze_with_llm(query)
            mutations = []
            
            for item in result:
                try:
                    mutation_type = MutationType(item.get("mutation_type", "encoding"))
                    mutations.append(MutationResult(
                        original_payload=payload,
                        mutated_payload=item["mutated_payload"],
                        mutation_type=mutation_type,
                        success_probability=float(item.get("success_probability", 0.5)),
                        complexity=int(item.get("complexity", 1)),
                        mutation_description=item.get("description", "LLM-generated mutation"),
                        timestamp=datetime.utcnow().isoformat(),
                        metadata={
                            "original_metadata": asdict(metadata),
                            "mutation_context": context,
                            "llm_response": item
                        }
                    ))
                except (ValueError, KeyError) as e:
                    logger.error(f"Failed to parse LLM mutation result: {str(e)}")
                    
            return mutations
            
        except Exception as e:
            logger.error(f"Failed to generate LLM mutations: {str(e)}")
            return []
            
    async def _analyze_with_llm(self, query: str) -> List[Dict]:
        """Get analysis from LLM"""
        try:
            result = await self._run_in_thread(generate_response, query)
            return json.loads(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse LLM response as JSON")
            return []
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            return []
            
    async def _run_in_thread(self, func, *args):
        """Run function in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, func, *args)

# Legacy support
async def mutate_payload_llm(payload: str, context: Dict) -> List[str]:
    """Legacy wrapper for backward compatibility"""
    mutator = PayloadMutator()
    mutations = await mutator.mutate_payload(payload, context)
    return [m.mutated_payload for m in mutations]
