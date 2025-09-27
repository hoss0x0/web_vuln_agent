"""RAG chain with advanced context handling and response generation."""

import os
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Union, Any
from dataclasses import dataclass
from datetime import datetime

import torch
from transformers import StoppingCriteria, StoppingCriteriaList

from rag_layer.llm_config import llm_manager
from rag_layer.retriever import retrieve_chunks
from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class RAGConfig:
    """Configuration for RAG chain"""
    top_k: int = 3
    context_window: int = 2048
    max_new_tokens: int = 300
    min_chunk_relevance: float = 0.7
    max_context_chunks: int = 5
    temperature: float = 0.7
    top_p: float = 0.9
    repetition_penalty: float = 1.1
    prompt_templates: Dict[str, str] = None
    response_prefixes: List[str] = None

    def __post_init__(self):
        if self.prompt_templates is None:
            self.prompt_templates = {
                "default": """Given the following context, answer the question comprehensively and accurately. 
If the context is insufficient, supplement with your knowledge while indicating what comes from context vs. general knowledge.

Context:
{context}

Question:
{query}

Provide a detailed answer with:
1. Direct response to the question
2. Supporting evidence from context
3. Any additional relevant information
4. Specific examples where applicable

Answer:""",
                "security": """Analyze the following security-related question using the provided context.
Focus on technical accuracy and security implications.

Context:
{context}

Security Question:
{query}

Provide a security analysis including:
1. Technical assessment
2. Security implications
3. Potential risks
4. Recommended mitigations
5. Best practices

Security Analysis:"""
            }
        if self.response_prefixes is None:
            self.response_prefixes = ["Answer:", "Security Analysis:"]

class ContextProcessor:
    """Process and optimize retrieval context"""

    @staticmethod
    def deduplicate_chunks(chunks: List[Dict]) -> List[Dict]:
        """Remove duplicate or near-duplicate chunks"""
        seen_contents = set()
        unique_chunks = []
        
        for chunk in chunks:
            content = chunk["content"].strip()
            if content not in seen_contents:
                seen_contents.add(content)
                unique_chunks.append(chunk)
        
        return unique_chunks

    @staticmethod
    def sort_by_relevance(chunks: List[Dict]) -> List[Dict]:
        """Sort chunks by relevance score"""
        return sorted(
            chunks,
            key=lambda x: float(x.get("relevance_score", 0)),
            reverse=True
        )

    @staticmethod
    def format_context(chunks: List[Dict], max_tokens: int) -> str:
        """Format chunks into context string with metadata"""
        context_parts = []
        total_tokens = 0
        
        for chunk in chunks:
            chunk_text = f"Source: {chunk.get('metadata', {}).get('source_file', 'Unknown')}\n"
            chunk_text += f"Relevance: {chunk.get('relevance_score', 'N/A')}\n"
            chunk_text += f"Content: {chunk['content']}\n"
            chunk_text += "---\n"
            
            # Approximate token count
            token_count = len(chunk_text.split())
            if total_tokens + token_count > max_tokens:
                break
                
            context_parts.append(chunk_text)
            total_tokens += token_count
            
        return "\n".join(context_parts)

class ResponseValidator:
    """Validate and improve generated responses"""

    @staticmethod
    def extract_answer(text: str, prefixes: List[str]) -> str:
        """Extract answer from generated text"""
        for prefix in prefixes:
            if prefix in text:
                return text.split(prefix)[-1].strip()
        return text.strip()

    @staticmethod
    def validate_response(response: str) -> bool:
        """Validate response quality and completeness"""
        if not response:
            return False
            
        # Check minimum length
        if len(response.split()) < 10:
            return False
            
        # Check for incomplete sentences
        if response[-1] not in ".!?":
            return False
            
        return True

class RAGChain:
    """Enhanced RAG chain with advanced features"""
    
    def __init__(self, config: Optional[RAGConfig] = None):
        """Initialize RAG chain with configuration"""
        self.config = config or self._load_config()
        self.context_processor = ContextProcessor()
        self.response_validator = ResponseValidator()

    def _load_config(self) -> RAGConfig:
        """Load configuration from YAML file"""
        try:
            config_path = Path("config/rag_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                config_dict = yaml.safe_load(f)
                return RAGConfig(**config_dict)
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {str(e)}")
            return RAGConfig()

    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        config = RAGConfig()
        config_dict = {
            "top_k": config.top_k,
            "context_window": config.context_window,
            "max_new_tokens": config.max_new_tokens,
            "min_chunk_relevance": config.min_chunk_relevance,
            "max_context_chunks": config.max_context_chunks,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "repetition_penalty": config.repetition_penalty,
            "prompt_templates": config.prompt_templates,
            "response_prefixes": config.response_prefixes
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False)

    def generate_response(
        self,
        query: str,
        template_key: str = "default",
        **kwargs
    ) -> Dict[str, Any]:
        """Generate response with error handling and validation"""
        try:
            # Get chunks from retriever
            chunks = retrieve_chunks(query, top_k=self.config.top_k)
            if not chunks:
                logger.warning("No relevant chunks found")
                
            # Process chunks
            chunks = self.context_processor.deduplicate_chunks(chunks)
            chunks = self.context_processor.sort_by_relevance(chunks)
            chunks = chunks[:self.config.max_context_chunks]
            
            # Format context
            context = self.context_processor.format_context(
                chunks,
                max_tokens=self.config.context_window
            )
            
            # Get prompt template
            prompt_template = self.config.prompt_templates.get(
                template_key,
                self.config.prompt_templates["default"]
            )
            
            # Format prompt
            prompt = prompt_template.format(context=context, query=query)
            
            # Generate response
            response = llm_manager.generate_text(
                prompt=prompt,
                max_length=self.config.context_window + self.config.max_new_tokens,
                temperature=self.config.temperature,
                top_p=self.config.top_p,
                repetition_penalty=self.config.repetition_penalty,
                **kwargs
            )
            
            # Extract and validate answer
            answer = self.response_validator.extract_answer(
                response,
                self.config.response_prefixes
            )
            
            if not self.response_validator.validate_response(answer):
                logger.warning("Generated response failed validation")
            
            # Return response with metadata
            return {
                "answer": answer,
                "metadata": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "query": query,
                    "template_used": template_key,
                    "chunk_count": len(chunks),
                    "context_length": len(context),
                    "response_length": len(answer)
                }
            }

        except Exception as e:
            logger.error(f"Response generation failed: {str(e)}")
            raise

# Initialize global RAG chain
rag_chain = RAGChain()
