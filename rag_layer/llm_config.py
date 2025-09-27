"""LLM configuration with model management and caching."""

import os
import logging
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from functools import lru_cache

import torch
from transformers import (
    AutoTokenizer, 
    AutoModelForCausalLM,
    PreTrainedModel,
    PreTrainedTokenizer
)
from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class LLMConfig:
    """Configuration for LLM loading and inference"""
    model_name: str = "mistralai/Mistral-7B-Instruct-v0.2"
    cache_dir: str = "models/cache"
    max_memory: Optional[Dict[int, str]] = None
    torch_dtype: torch.dtype = torch.float16
    load_in_8bit: bool = False
    device_map: str = "auto"
    use_cache: bool = True
    max_length: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    repetition_penalty: float = 1.1
    num_return_sequences: int = 1

class LLMManager:
    """Enhanced LLM manager with caching and resource management"""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        """Initialize LLM manager with configuration"""
        self.config = config or self._load_config()
        self._setup_cache_dir()
        self.model = None
        self.tokenizer = None

    def _load_config(self) -> LLMConfig:
        """Load configuration from YAML file or use defaults"""
        try:
            config_path = Path("config/llm_config.yaml")
            if not config_path.exists():
                self._create_default_config(config_path)
                
            with open(config_path, "r") as f:
                config_dict = yaml.safe_load(f)
                return LLMConfig(**config_dict)
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {str(e)}")
            return LLMConfig()

    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file"""
        default_config = {
            "model_name": "mistralai/Mistral-7B-Instruct-v0.2",
            "cache_dir": "models/cache",
            "torch_dtype": "float16",
            "load_in_8bit": False,
            "device_map": "auto",
            "use_cache": True,
            "max_length": 2048,
            "temperature": 0.7,
            "top_p": 0.9,
            "repetition_penalty": 1.1,
            "num_return_sequences": 1
        }
        
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False)

    def _setup_cache_dir(self) -> None:
        """Setup model cache directory"""
        cache_dir = Path(self.config.cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        os.environ["TRANSFORMERS_CACHE"] = str(cache_dir)

    @property
    def device(self) -> torch.device:
        """Get appropriate torch device"""
        if torch.cuda.is_available():
            return torch.device("cuda")
        elif torch.backends.mps.is_available():
            return torch.device("mps")
        return torch.device("cpu")

    def _get_model_config(self) -> Dict[str, Any]:
        """Get model configuration dictionary"""
        return {
            "torch_dtype": self.config.torch_dtype,
            "device_map": self.config.device_map,
            "max_memory": self.config.max_memory,
            "load_in_8bit": self.config.load_in_8bit,
            "use_cache": self.config.use_cache
        }

    @lru_cache(maxsize=1)
    def get_tokenizer(self) -> PreTrainedTokenizer:
        """Get or load tokenizer with caching"""
        if self.tokenizer is None:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_name,
                    cache_dir=self.config.cache_dir
                )
                logger.info(f"Loaded tokenizer: {self.config.model_name}")
            except Exception as e:
                logger.error(f"Failed to load tokenizer: {str(e)}")
                raise
        return self.tokenizer

    @lru_cache(maxsize=1)
    def get_model(self) -> PreTrainedModel:
        """Get or load model with caching"""
        if self.model is None:
            try:
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_name,
                    cache_dir=self.config.cache_dir,
                    **self._get_model_config()
                )
                logger.info(
                    f"Loaded model: {self.config.model_name} "
                    f"on device: {self.device}"
                )
            except Exception as e:
                logger.error(f"Failed to load model: {str(e)}")
                raise
        return self.model

    def generate_text(
        self,
        prompt: str,
        max_length: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate text using the model"""
        try:
            tokenizer = self.get_tokenizer()
            model = self.get_model()

            # Prepare inputs
            inputs = tokenizer(
                prompt,
                return_tensors="pt",
                padding=True,
                truncation=True
            ).to(self.device)

            # Set generation parameters
            gen_kwargs = {
                "max_length": max_length or self.config.max_length,
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "repetition_penalty": self.config.repetition_penalty,
                "num_return_sequences": self.config.num_return_sequences,
                "pad_token_id": tokenizer.pad_token_id,
                **kwargs
            }

            # Generate
            with torch.no_grad():
                output_ids = model.generate(**inputs, **gen_kwargs)

            return tokenizer.decode(output_ids[0], skip_special_tokens=True)

        except Exception as e:
            logger.error(f"Text generation failed: {str(e)}")
            raise

    def clear_cache(self) -> None:
        """Clear model and tokenizer cache"""
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None
        torch.cuda.empty_cache()
        logger.info("Cleared model cache and CUDA memory")

# Initialize global LLM manager
llm_manager = LLMManager()
model = llm_manager.get_model()
tokenizer = llm_manager.get_tokenizer()
