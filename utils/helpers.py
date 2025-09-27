"""Advanced text processing utilities with enhanced cleaning and chunking."""

import re
import html
import logging
import unicodedata
from typing import List, Dict, Optional, Union, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class TextConfig:
    """Configuration for text processing"""
    normalize_unicode: bool = True
    fix_encoding: bool = True
    remove_control_chars: bool = True
    decode_html: bool = True
    preserve_code: bool = True
    max_length: int = 500
    min_chunk_size: int = 50
    overlap: int = 50
    respect_sentences: bool = True
    preserve_urls: bool = True
    max_consecutive_newlines: int = 2
    threads: int = 4

class TextProcessor:
    """Advanced text processing with multiple cleaning strategies"""
    
    # Regex patterns for different text elements
    PATTERNS = {
        'url': r'https?://\S+|www\.\S+',
        'email': r'\S+@\S+\.\S+',
        'code_block': r'```[\s\S]*?```|`[^`]+`',
        'html_tag': r'<[^>]+>',
        'extra_space': r'\s+',
        'control_char': r'[\x00-\x1F\x7F-\x9F]',
        'consecutive_newlines': r'\n{3,}',
        'sentence_end': r'(?<=[.!?])\s+(?=[A-Z])',
    }
    
    def __init__(self, config: Optional[TextConfig] = None):
        """Initialize text processor with configuration"""
        self.config = config or TextConfig()
        self._compile_patterns()
        
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency"""
        self.compiled_patterns = {
            name: re.compile(pattern, re.MULTILINE)
            for name, pattern in self.PATTERNS.items()
        }

    def clean_text(
        self,
        text: str,
        normalize_unicode: Optional[bool] = None,
        fix_encoding: Optional[bool] = None,
        remove_control_chars: Optional[bool] = None,
        decode_html: Optional[bool] = None,
        preserve_code: Optional[bool] = None
    ) -> str:
        """
        Clean text with advanced processing
        
        Args:
            text: Input text to clean
            normalize_unicode: Whether to normalize Unicode characters
            fix_encoding: Whether to fix encoding issues
            remove_control_chars: Whether to remove control characters
            decode_html: Whether to decode HTML entities
            preserve_code: Whether to preserve code blocks
            
        Returns:
            Cleaned text
        """
        if not text:
            return ""
            
        try:
            # Use provided options or fall back to config defaults
            normalize_unicode = normalize_unicode if normalize_unicode is not None else self.config.normalize_unicode
            fix_encoding = fix_encoding if fix_encoding is not None else self.config.fix_encoding
            remove_control_chars = remove_control_chars if remove_control_chars is not None else self.config.remove_control_chars
            decode_html = decode_html if decode_html is not None else self.config.decode_html
            preserve_code = preserve_code if preserve_code is not None else self.config.preserve_code
            
            # Store code blocks if needed
            code_blocks = []
            if preserve_code:
                code_blocks = self.compiled_patterns['code_block'].findall(text)
                for i, block in enumerate(code_blocks):
                    text = text.replace(block, f'__CODE_BLOCK_{i}__')
            
            # Store URLs if needed
            urls = []
            if self.config.preserve_urls:
                urls = self.compiled_patterns['url'].findall(text)
                for i, url in enumerate(urls):
                    text = text.replace(url, f'__URL_{i}__')
            
            # Basic cleaning
            if fix_encoding:
                text = text.encode('utf-8', errors='ignore').decode('utf-8')
            
            if normalize_unicode:
                text = unicodedata.normalize('NFKC', text)
            
            if remove_control_chars:
                text = self.compiled_patterns['control_char'].sub(' ', text)
            
            if decode_html:
                text = html.unescape(text)
            
            # Remove excessive whitespace
            text = self.compiled_patterns['extra_space'].sub(' ', text)
            text = self.compiled_patterns['consecutive_newlines'].sub('\n\n', text)
            text = text.strip()
            
            # Restore code blocks
            if preserve_code:
                for i, block in enumerate(code_blocks):
                    text = text.replace(f'__CODE_BLOCK_{i}__', block)
            
            # Restore URLs
            if self.config.preserve_urls:
                for i, url in enumerate(urls):
                    text = text.replace(f'__URL_{i}__', url)
            
            return text
            
        except Exception as e:
            logger.error(f"Text cleaning failed: {str(e)}")
            return text

    def _find_sentence_boundaries(self, text: str) -> List[int]:
        """Find sentence boundary positions"""
        return [m.start() for m in self.compiled_patterns['sentence_end'].finditer(text)]

    def chunk_text(
        self,
        text: str,
        max_length: Optional[int] = None,
        min_chunk_size: Optional[int] = None,
        overlap: Optional[int] = None,
        respect_sentences: Optional[bool] = None
    ) -> List[str]:
        """
        Split text into chunks with advanced options
        
        Args:
            text: Text to split into chunks
            max_length: Maximum length of each chunk
            min_chunk_size: Minimum chunk size to keep
            overlap: Number of words to overlap between chunks
            respect_sentences: Whether to respect sentence boundaries
            
        Returns:
            List of text chunks
        """
        if not text:
            return []
            
        try:
            # Use provided options or fall back to config defaults
            max_length = max_length if max_length is not None else self.config.max_length
            min_chunk_size = min_chunk_size if min_chunk_size is not None else self.config.min_chunk_size
            overlap = overlap if overlap is not None else self.config.overlap
            respect_sentences = respect_sentences if respect_sentences is not None else self.config.respect_sentences
            
            # Find sentence boundaries if needed
            sentence_bounds = []
            if respect_sentences:
                sentence_bounds = self._find_sentence_boundaries(text)
            
            # Split into initial chunks
            words = text.split()
            chunks = []
            current_chunk = []
            current_size = 0
            
            for word in words:
                word_size = len(word) + 1  # +1 for space
                
                # Check if adding this word would exceed max length
                if current_size + word_size > max_length and current_chunk:
                    # Find nearest sentence boundary if needed
                    if respect_sentences and sentence_bounds:
                        current_text = ' '.join(current_chunk)
                        nearest_bound = max((b for b in sentence_bounds if b <= len(current_text)), default=None)
                        if nearest_bound:
                            chunks.append(current_text[:nearest_bound].strip())
                            current_chunk = [w for w in current_text[nearest_bound:].split() if w]
                            current_size = sum(len(w) + 1 for w in current_chunk)
                            continue
                    
                    chunks.append(' '.join(current_chunk))
                    
                    # Handle overlap
                    if overlap > 0:
                        current_chunk = current_chunk[-overlap:]
                        current_size = sum(len(w) + 1 for w in current_chunk)
                    else:
                        current_chunk = []
                        current_size = 0
                
                current_chunk.append(word)
                current_size += word_size
            
            # Add final chunk
            if current_chunk:
                chunks.append(' '.join(current_chunk))
            
            # Filter out chunks that are too small
            chunks = [chunk for chunk in chunks if len(chunk) >= min_chunk_size]
            
            return chunks
            
        except Exception as e:
            logger.error(f"Text chunking failed: {str(e)}")
            return [text]

    def process_batch(
        self,
        texts: List[str],
        clean_options: Optional[Dict] = None,
        chunk_options: Optional[Dict] = None
    ) -> List[str]:
        """
        Process multiple texts in parallel
        
        Args:
            texts: List of texts to process
            clean_options: Options for text cleaning
            chunk_options: Options for text chunking
            
        Returns:
            List of processed chunks
        """
        clean_options = clean_options or {}
        chunk_options = chunk_options or {}
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                # Clean texts in parallel
                cleaned_texts = list(executor.map(
                    lambda t: self.clean_text(t, **clean_options),
                    texts
                ))
                
                # Chunk cleaned texts in parallel
                chunked_lists = list(executor.map(
                    lambda t: self.chunk_text(t, **chunk_options),
                    cleaned_texts
                ))
                
            # Flatten list of lists
            return [chunk for chunks in chunked_lists for chunk in chunks]
            
        except Exception as e:
            logger.error(f"Batch processing failed: {str(e)}")
            return texts

# Initialize global text processor
text_processor = TextProcessor()

def clean_text(text: str, **kwargs) -> str:
    """Clean text using global processor"""
    return text_processor.clean_text(text, **kwargs)

def chunk_text(text: str, **kwargs) -> List[str]:
    """Chunk text using global processor"""
    return text_processor.chunk_text(text, **kwargs)
