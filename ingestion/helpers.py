"""Advanced text processing and chunking utilities."""

import re
import html
import logging
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import unicodedata
from collections import Counter

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class ChunkConfig:
    """Configuration for text chunking"""
    chunk_size: int = 500
    overlap: int = 50
    respect_sentences: bool = True
    min_chunk_size: int = 100
    max_chunk_size: int = 1000
    preserve_code_blocks: bool = True
    balance_chunks: bool = True

@dataclass
class TextStats:
    """Statistics about processed text"""
    original_length: int
    cleaned_length: int
    char_count: int
    word_count: int
    sentence_count: int
    avg_word_length: float
    avg_sentence_length: float
    special_chars: Dict[str, int]
    encoding_types: Dict[str, int]

def clean_text(text: str,
               normalize_unicode: bool = True,
               fix_encoding: bool = True,
               remove_control_chars: bool = True,
               decode_html: bool = True,
               preserve_code: bool = True) -> str:
    """
    Advanced text cleaning with multiple options
    
    Args:
        text: Input text to clean
        normalize_unicode: Whether to normalize Unicode characters
        fix_encoding: Whether to fix common encoding issues
        remove_control_chars: Whether to remove control characters
        decode_html: Whether to decode HTML entities
        preserve_code: Whether to preserve code blocks
        
    Returns:
        Cleaned text
    """
    try:
        if not text:
            return ""
            
        # Extract code blocks if needed
        code_blocks = []
        if preserve_code:
            code_blocks = re.findall(r'```[\s\S]*?```|`[^`]+`', text)
            for i, block in enumerate(code_blocks):
                text = text.replace(block, f'__CODE_BLOCK_{i}__')
                
        # Basic cleaning
        text = text.replace("\r", "")
        text = text.strip()
        
        # Fix encoding issues
        if fix_encoding:
            text = text.encode('utf-8', errors='ignore').decode('utf-8')
            
        # Normalize Unicode
        if normalize_unicode:
            text = unicodedata.normalize('NFKC', text)
            
        # Remove control characters
        if remove_control_chars:
            text = ''.join(char for char in text if unicodedata.category(char)[0] != 'C')
            
        # Decode HTML entities
        if decode_html:
            text = html.unescape(text)
            
        # Fix common issues
        text = re.sub(r'\s+', ' ', text)  # Multiple spaces
        text = re.sub(r'[\u200b\ufeff]', '', text)  # Zero-width spaces
        
        # Restore code blocks
        if preserve_code:
            for i, block in enumerate(code_blocks):
                text = text.replace(f'__CODE_BLOCK_{i}__', block)
                
        return text
        
    except Exception as e:
        logger.error(f"Text cleaning failed: {str(e)}")
        return text

def analyze_text(text: str) -> TextStats:
    """
    Analyze text and generate statistics
    
    Args:
        text: Text to analyze
        
    Returns:
        TextStats object with analysis results
    """
    try:
        # Basic counts
        original_length = len(text)
        cleaned = clean_text(text)
        cleaned_length = len(cleaned)
        
        # Word analysis
        words = re.findall(r'\w+', cleaned)
        word_count = len(words)
        char_count = sum(len(word) for word in words)
        
        # Sentence analysis
        sentences = re.split(r'[.!?]+', cleaned)
        sentence_count = len([s for s in sentences if s.strip()])
        
        # Averages
        avg_word_length = char_count / word_count if word_count > 0 else 0
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0
        
        # Special character analysis
        special_chars = Counter(c for c in text if not c.isalnum() and not c.isspace())
        
        # Encoding analysis
        encoding_types = {
            'ascii': sum(1 for c in text if ord(c) < 128),
            'unicode': sum(1 for c in text if ord(c) >= 128)
        }
        
        return TextStats(
            original_length=original_length,
            cleaned_length=cleaned_length,
            char_count=char_count,
            word_count=word_count,
            sentence_count=sentence_count,
            avg_word_length=avg_word_length,
            avg_sentence_length=avg_sentence_length,
            special_chars=dict(special_chars),
            encoding_types=encoding_types
        )
        
    except Exception as e:
        logger.error(f"Text analysis failed: {str(e)}")
        return None

def find_sentence_boundaries(text: str) -> List[int]:
    """Find sentence boundary positions"""
    boundaries = []
    
    # Regular expression for sentence boundaries
    sentence_pattern = re.compile(
        r'(?<=[.!?])\s+(?=[A-Z])|'  # Standard sentence end
        r'(?<=\n)\s*(?=[A-Z])|'     # New line with capital
        r'(?<=[.!?])\s*$'           # End of text
    )
    
    for match in sentence_pattern.finditer(text):
        boundaries.append(match.start())
        
    return boundaries

def chunk_text(text: str,
               config: Optional[ChunkConfig] = None) -> List[str]:
    """
    Advanced text chunking with multiple strategies
    
    Args:
        text: Text to chunk
        config: Optional chunking configuration
        
    Returns:
        List of text chunks
    """
    try:
        config = config or ChunkConfig()
        
        if not text:
            return []
            
        # Extract and protect code blocks
        code_blocks = []
        if config.preserve_code_blocks:
            code_blocks = re.findall(r'```[\s\S]*?```|`[^`]+`', text)
            for i, block in enumerate(code_blocks):
                text = text.replace(block, f'__CODE_BLOCK_{i}__')
                
        # Find sentence boundaries if needed
        sentence_bounds = []
        if config.respect_sentences:
            sentence_bounds = find_sentence_boundaries(text)
            
        # Create initial chunks
        words = text.split()
        chunks = []
        current_chunk = []
        current_size = 0
        
        for word in words:
            word_size = len(word) + 1  # +1 for space
            
            # Check if adding this word would exceed max size
            if current_size + word_size > config.max_chunk_size and current_chunk:
                chunks.append(' '.join(current_chunk))
                
                # Handle overlap
                if config.overlap > 0:
                    overlap_words = current_chunk[-config.overlap:]
                    current_chunk = overlap_words
                    current_size = sum(len(w) + 1 for w in overlap_words)
                else:
                    current_chunk = []
                    current_size = 0
                    
            current_chunk.append(word)
            current_size += word_size
            
        # Add final chunk
        if current_chunk:
            chunks.append(' '.join(current_chunk))
            
        # Respect sentence boundaries if needed
        if config.respect_sentences:
            adjusted_chunks = []
            for chunk in chunks:
                bounds = find_sentence_boundaries(chunk)
                if bounds:
                    # Split at last sentence boundary that doesn't exceed max_chunk_size
                    for i in reversed(bounds):
                        if i <= config.max_chunk_size:
                            part1 = chunk[:i].strip()
                            part2 = chunk[i:].strip()
                            if part1:
                                adjusted_chunks.append(part1)
                            if part2:
                                adjusted_chunks.append(part2)
                            break
                    else:
                        adjusted_chunks.append(chunk)
                else:
                    adjusted_chunks.append(chunk)
            chunks = adjusted_chunks
            
        # Balance chunk sizes if needed
        if config.balance_chunks and len(chunks) > 1:
            avg_size = sum(len(c) for c in chunks) / len(chunks)
            balanced_chunks = []
            current = []
            current_size = 0
            
            for chunk in chunks:
                if current_size + len(chunk) > avg_size * 1.5 and current:
                    balanced_chunks.append(' '.join(current))
                    current = []
                    current_size = 0
                current.append(chunk)
                current_size += len(chunk)
                
            if current:
                balanced_chunks.append(' '.join(current))
            chunks = balanced_chunks
            
        # Restore code blocks
        if config.preserve_code_blocks:
            for i, block in enumerate(code_blocks):
                for j in range(len(chunks)):
                    chunks[j] = chunks[j].replace(f'__CODE_BLOCK_{i}__', block)
                    
        # Filter out chunks that are too small
        chunks = [c for c in chunks if len(c) >= config.min_chunk_size]
        
        return chunks
        
    except Exception as e:
        logger.error(f"Text chunking failed: {str(e)}")
        return [text]  # Return original text as single chunk on error

def process_text_parallel(texts: List[str],
                         chunk_config: Optional[ChunkConfig] = None,
                         max_workers: int = 4) -> List[str]:
    """
    Process multiple texts in parallel
    
    Args:
        texts: List of texts to process
        chunk_config: Optional chunking configuration
        max_workers: Maximum number of parallel workers
        
    Returns:
        List of processed chunks
    """
    try:
        chunk_config = chunk_config or ChunkConfig()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Clean texts in parallel
            cleaned_texts = list(executor.map(clean_text, texts))
            
            # Chunk cleaned texts in parallel
            chunked_lists = list(executor.map(
                lambda t: chunk_text(t, chunk_config),
                cleaned_texts
            ))
            
        # Flatten list of lists into single list
        return [chunk for chunks in chunked_lists for chunk in chunks]
        
    except Exception as e:
        logger.error(f"Parallel processing failed: {str(e)}")
        return texts  # Return original texts on error
