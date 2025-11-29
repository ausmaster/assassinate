"""Structured logging configuration for Assassinate.

Provides consistent logging across all modules with context and performance tracking.
"""

from __future__ import annotations

import logging
import sys
import time
from contextvars import ContextVar
from typing import Any

# Context variable for tracking current call ID
current_call_id: ContextVar[int | None] = ContextVar("current_call_id", default=None)


class ContextFormatter(logging.Formatter):
    """Custom formatter that includes call context."""

    def format(self, record: logging.LogRecord) -> str:
        # Add call_id to record if available
        call_id = current_call_id.get()
        if call_id is not None:
            record.call_id = call_id  # type: ignore
        else:
            record.call_id = "-"  # type: ignore

        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    structured: bool = True,
) -> None:
    """Setup logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        structured: Use structured logging format with context
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger("assassinate")
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()  # Remove any existing handlers

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)

    if structured:
        # Structured format with context
        fmt = "%(asctime)s [%(levelname)8s] [%(call_id)s] %(name)s - %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
    else:
        # Simple format
        fmt = "%(levelname)s: %(message)s"
        datefmt = None

    formatter = ContextFormatter(fmt, datefmt=datefmt)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"assassinate.{name}")


class PerformanceLogger:
    """Context manager for logging operation performance."""

    def __init__(self, logger: logging.Logger, operation: str, **context: Any):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time: float = 0

    def __enter__(self) -> PerformanceLogger:
        self.start_time = time.perf_counter()
        if self.logger.isEnabledFor(logging.DEBUG):
            ctx = " ".join(f"{k}={v}" for k, v in self.context.items())
            self.logger.debug(f"{self.operation} started {ctx}".strip())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        elapsed = (time.perf_counter() - self.start_time) * 1000  # ms

        if exc_type is not None:
            # Operation failed
            ctx = " ".join(f"{k}={v}" for k, v in self.context.items())
            self.logger.error(
                f"{self.operation} failed in {elapsed:.2f}ms {ctx} error={exc_type.__name__}: {exc_val}".strip()
            )
        else:
            # Operation succeeded
            if self.logger.isEnabledFor(logging.DEBUG):
                ctx = " ".join(f"{k}={v}" for k, v in self.context.items())
                self.logger.debug(f"{self.operation} completed in {elapsed:.2f}ms {ctx}".strip())
