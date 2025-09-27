"""Advanced logging configuration with enhanced features and security monitoring."""

import os
import sys
import json
import time
import atexit
from pathlib import Path
from datetime import datetime
from functools import wraps
from typing import Any, Dict, Optional, Union, Callable
from loguru import logger
import logging

class SecurityLogger:
    """Enhanced logging system with security features and advanced configuration."""
    
    # Log levels with their corresponding numeric values
    LOG_LEVELS = {
        "TRACE": 5,
        "DEBUG": 10,
        "INFO": 20,
        "SUCCESS": 25,
        "WARNING": 30,
        "ERROR": 40,
        "CRITICAL": 50
    }

    def __init__(
        self,
        log_path: Union[str, Path] = "logs",
        app_name: str = "agent",
        rotation: str = "1 day",
        retention: str = "7 days",
        compression: str = "zip",
        level: str = "INFO",
        serialize: bool = True,
        backtrace: bool = True,
        diagnose: bool = True,
        enqueue: bool = True,
        catch: bool = True
    ):
        """Initialize the security logger with advanced configuration."""
        self.log_path = Path(log_path)
        self.app_name = app_name
        self._setup_log_directory()
        self._configure_logger(
            rotation=rotation,
            retention=retention,
            compression=compression,
            level=level,
            serialize=serialize,
            backtrace=backtrace,
            diagnose=diagnose,
            enqueue=enqueue,
            catch=catch
        )
        self._setup_error_handler()
        atexit.register(self._cleanup)

    def _setup_log_directory(self) -> None:
        """Create log directory with proper permissions."""
        try:
            self.log_path.mkdir(parents=True, exist_ok=True)
            self.log_path.chmod(0o750)  # Secure permissions
        except Exception as e:
            sys.stderr.write(f"Failed to create log directory: {str(e)}\n")
            raise

    def _configure_logger(self, **kwargs) -> None:
        """Configure logger with advanced options and multiple sinks."""
        # Remove default handler
        logger.remove()

        # Add stderr handler for interactive use
        logger.add(
            sys.stderr,
            format="<level>{level: <8}</level> | <green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
                   "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
            level=kwargs.get("level", "INFO"),
            backtrace=kwargs.get("backtrace", True),
            diagnose=kwargs.get("diagnose", True),
            enqueue=kwargs.get("enqueue", True),
            catch=kwargs.get("catch", True)
        )

        # Add file handler for main log
        logger.add(
            self.log_path / f"{self.app_name}.log",
            rotation=kwargs.get("rotation", "1 day"),
            retention=kwargs.get("retention", "7 days"),
            compression=kwargs.get("compression", "zip"),
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
            level=kwargs.get("level", "INFO"),
            serialize=kwargs.get("serialize", True),
            backtrace=kwargs.get("backtrace", True),
            diagnose=kwargs.get("diagnose", True),
            enqueue=kwargs.get("enqueue", True),
            catch=kwargs.get("catch", True)
        )

        # Add separate handler for security events
        logger.add(
            self.log_path / f"{self.app_name}_security.log",
            rotation=kwargs.get("rotation", "1 day"),
            retention=kwargs.get("retention", "30 days"),
            compression=kwargs.get("compression", "zip"),
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
            filter=lambda record: "security" in record["extra"],
            level="INFO",
            serialize=True,
            enqueue=True
        )

    def _setup_error_handler(self) -> None:
        """Configure system-wide exception handler."""
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            logger.opt(exception=(exc_type, exc_value, exc_traceback)).error("Uncaught exception:")

        sys.excepthook = handle_exception

    def _cleanup(self) -> None:
        """Cleanup operations on system exit."""
        logger.info("Shutting down logging system...")
        for handler in logger._core.handlers.values():
            handler.stop()

    @staticmethod
    def log_execution_time(func: Callable) -> Callable:
        """Decorator to log function execution time."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.debug(f"Function {func.__name__} executed in {execution_time:.2f} seconds")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(
                    f"Function {func.__name__} failed after {execution_time:.2f} seconds with error: {str(e)}"
                )
                raise
        return wrapper

    @staticmethod
    def log_security_event(
        event_type: str,
        details: Dict[str, Any],
        level: str = "INFO"
    ) -> None:
        """Log security-related events with additional context."""
        try:
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "details": details
            }
            logger.bind(security=True).log(
                level,
                f"Security Event: {event_type}\n{json.dumps(log_data, indent=2)}"
            )
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")

def setup_logger(
    name: Optional[str] = None,
    level: str = "INFO"
) -> logging.Logger:
    """Initialize and configure a logger instance."""
    logger.remove()
    logger.add(
        sys.stderr,
        format="<level>{level: <8}</level> | <green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
        level=level
    )
    return logger

def log_event(
    message: str,
    level: str = "INFO",
    **kwargs
) -> None:
    """Enhanced logging with additional context and error handling."""
    try:
        log_func = getattr(logger, level.lower())
        if kwargs:
            logger.bind(**kwargs).log(level, message)
        else:
            log_func(message)
    except AttributeError:
        logger.error(f"Invalid log level: {level}")
    except Exception as e:
        logger.error(f"Logging failed: {str(e)}")

# Initialize the security logger
security_logger = SecurityLogger()
