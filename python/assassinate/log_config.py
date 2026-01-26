"""Structured logging configuration for Assassinate.

Provides consistent logging across all modules with context tracking,
colored console output, and custom log levels.

Environment Variables:
    ASSASSINATE_LOG_LEVEL: Set log level (DEBUG, VERBOSE, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    ASSASSINATE_LOG_FILE: Path to log file (optional, logs to file in addition to stderr)

Custom Log Levels:
    VERBOSE (15): More verbose than INFO, less than DEBUG
    SUCCESS (25): Highlight successful operations (session established, kill confirmed)

Example:
    # Via environment variables (recommended)
    $ ASSASSINATE_LOG_LEVEL=DEBUG ASSASSINATE_LOG_FILE=/tmp/assassinate.log python script.py

    # Programmatically
    >>> from assassinate.log_config import setup_logging
    >>> setup_logging(level="DEBUG", log_file="/tmp/assassinate.log")

    # Use SUCCESS level for important wins
    >>> logger.success("Session established!")
"""

from __future__ import annotations

import logging
import os
import sys
import time
from copy import copy
from contextvars import ContextVar
from pathlib import Path
from typing import Any

# =============================================================================
# Environment Variables
# =============================================================================

ENV_LOG_LEVEL = "ASSASSINATE_LOG_LEVEL"
ENV_LOG_FILE = "ASSASSINATE_LOG_FILE"

# =============================================================================
# Custom Log Levels
# =============================================================================

# Add custom log levels (between standard levels)
VERBOSE = 15  # Between DEBUG (10) and INFO (20)
SUCCESS = 25  # Between INFO (20) and WARNING (30)

# Register custom levels with logging module
logging.addLevelName(VERBOSE, "VERBOSE")
logging.addLevelName(SUCCESS, "SUCCESS")


def _verbose(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """Log a VERBOSE level message."""
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kwargs)


def _success(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """Log a SUCCESS level message."""
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)


# Add methods to Logger class
logging.Logger.verbose = _verbose  # type: ignore
logging.Logger.success = _success  # type: ignore

# Also add to logging module for convenience
logging.VERBOSE = VERBOSE  # type: ignore
logging.SUCCESS = SUCCESS  # type: ignore


# =============================================================================
# Color Configuration (256-color ANSI)
# =============================================================================

# Short level codes for compact console output
LEVEL_SHORT_CODES = {
    "DEBUG": "DBUG",
    "VERBOSE": "VERB",
    "INFO": "INFO",
    "SUCCESS": "SUCC",
    "WARNING": "WARN",
    "ERROR": "ERRR",
    "CRITICAL": "CRIT",
}

# 256-color ANSI codes for each level
LEVEL_COLORS = {
    "DEBUG": 242,     # grey
    "VERBOSE": 242,   # grey
    "INFO": 69,       # blue
    "SUCCESS": 118,   # green
    "WARNING": 208,   # orange
    "ERROR": 196,     # red
    "CRITICAL": 196,  # red
}

# ANSI escape sequences
COLOR_PREFIX = "\033[1;38;5;"  # Bold + 256-color
COLOR_RESET = "\033[0m"


def colorize(text: str, level: str = "INFO") -> str:
    """Colorize text based on log level.

    Args:
        text: Text to colorize
        level: Log level name (determines color)

    Returns:
        Colorized text with ANSI escape codes
    """
    color_code = LEVEL_COLORS.get(level, 15)  # default white
    return f"{COLOR_PREFIX}{color_code}m{text}{COLOR_RESET}"


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    # Check for NO_COLOR environment variable (standard)
    if os.environ.get("NO_COLOR"):
        return False
    # Check if stdout is a TTY
    if not hasattr(sys.stderr, "isatty"):
        return False
    if not sys.stderr.isatty():
        return False
    # Check for dumb terminal
    if os.environ.get("TERM") == "dumb":
        return False
    return True


# =============================================================================
# Formatters
# =============================================================================

# Module name prefixes to strip for cleaner console output
STRIP_PREFIXES = ("assassinate.", "msf.")


class ColoredFormatter(logging.Formatter):
    """Pretty colored formatter for console output.

    Features:
    - Short level codes: [SUCC], [VERB], [DBUG], etc.
    - 256-color ANSI codes per level
    - Strips module prefixes for cleaner output
    - Optional message coloring for SUCCESS/WARNING/ERROR
    """

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self._use_colors = use_colors and supports_color()

    def format(self, record: logging.LogRecord) -> str:
        # Make a copy to avoid modifying the original
        record = copy(record)

        # Get short level code
        level_short = LEVEL_SHORT_CODES.get(record.levelname, record.levelname[:4])

        # Strip module prefixes for cleaner output
        name = record.name
        for prefix in STRIP_PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break

        # Format the level tag
        level_tag = f"[{level_short}]"

        if self._use_colors:
            # Colorize the level tag
            level_tag = colorize(level_tag, record.levelname)

            # Colorize entire message for important levels
            if record.levelname in ("SUCCESS", "ERROR", "CRITICAL", "WARNING"):
                record.msg = colorize(str(record.msg), record.levelname)

        # Build the final message
        if name:
            return f"{level_tag} {name}: {record.getMessage()}"
        return f"{level_tag} {record.getMessage()}"


class FileFormatter(logging.Formatter):
    """Detailed formatter for file output.

    Includes timestamps, full module path, and line numbers for debugging.
    """

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s %(filename)s:%(lineno)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


# Context variable for tracking current call ID (for advanced use)
current_call_id: ContextVar[int | None] = ContextVar("current_call_id", default=None)

# Track if logging has been configured
_logging_configured = False


# =============================================================================
# Main Setup Functions
# =============================================================================

def setup_logging(
    level: str | None = None,
    log_file: str | Path | None = None,
    colors: bool = True,
    force: bool = False,
) -> None:
    """Setup logging configuration for both Python and Rust layers.

    Configures logging for both 'assassinate' (Python) and 'msf' (Rust via pyo3-log)
    loggers to ensure unified output.

    Args:
        level: Log level (DEBUG, VERBOSE, INFO, SUCCESS, WARNING, ERROR, CRITICAL).
               Defaults to ASSASSINATE_LOG_LEVEL env var, or "WARNING".
        log_file: Optional file path for log output.
                  Defaults to ASSASSINATE_LOG_FILE env var if set.
        colors: Enable colored console output (default True)
        force: Re-configure even if already configured

    Example:
        >>> setup_logging(level="DEBUG", log_file="/tmp/assassinate.log")
        >>> setup_logging(level="VERBOSE")  # More verbose than INFO
    """
    global _logging_configured

    if _logging_configured and not force:
        return

    # Read from environment if not provided
    if level is None:
        level = os.environ.get(ENV_LOG_LEVEL, "WARNING")
    if log_file is None:
        log_file = os.environ.get(ENV_LOG_FILE)

    # Handle custom level names
    level_upper = level.upper()
    if level_upper == "VERBOSE":
        log_level = VERBOSE
    elif level_upper == "SUCCESS":
        log_level = SUCCESS
    else:
        log_level = getattr(logging, level_upper, logging.INFO)

    # Create formatters
    console_formatter = ColoredFormatter(use_colors=colors)
    file_formatter = FileFormatter()

    # Configure both assassinate (Python) and msf (Rust) loggers
    for logger_name in ("assassinate", "msf"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)
        logger.handlers.clear()  # Remove any existing handlers

        # Console handler (stderr) with colored output
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # Optional file handler with detailed format
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

    _logging_configured = True


def add_file_handler(log_file: str | Path, level: str | None = None) -> None:
    """Add a file handler to existing logging configuration.

    Args:
        log_file: Path to log file
        level: Optional level for file handler (defaults to current logger level)

    Example:
        >>> add_file_handler("/tmp/debug.log", level="DEBUG")
    """
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_formatter = FileFormatter()

    for logger_name in ("assassinate", "msf"):
        logger = logging.getLogger(logger_name)

        # Determine level
        if level:
            level_upper = level.upper()
            if level_upper == "VERBOSE":
                file_level = VERBOSE
            elif level_upper == "SUCCESS":
                file_level = SUCCESS
            else:
                file_level = getattr(logging, level_upper, logger.level)
        else:
            file_level = logger.level

        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(file_level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module.

    The returned logger has .verbose() and .success() methods in addition
    to the standard .debug(), .info(), .warning(), .error(), .critical().

    Args:
        name: Module name (typically __name__ or short name like "hideout")

    Returns:
        Logger instance with custom level methods

    Example:
        >>> logger = get_logger("contract")
        >>> logger.success("Session established!")
        >>> logger.verbose("Detailed operation info")
    """
    return logging.getLogger(f"assassinate.{name}")


# =============================================================================
# Runtime Configuration
# =============================================================================

def set_level(level: str) -> None:
    """Change log level at runtime.

    Args:
        level: New log level (DEBUG, VERBOSE, INFO, SUCCESS, WARNING, ERROR, CRITICAL)

    Example:
        >>> set_level("DEBUG")   # Enable verbose logging
        >>> set_level("VERBOSE") # Slightly less verbose
        >>> set_level("WARNING") # Quiet mode
    """
    level_upper = level.upper()
    if level_upper == "VERBOSE":
        log_level = VERBOSE
    elif level_upper == "SUCCESS":
        log_level = SUCCESS
    else:
        log_level = getattr(logging, level_upper, logging.INFO)

    for logger_name in ("assassinate", "msf"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)
        for handler in logger.handlers:
            handler.setLevel(log_level)


def toggle_log_level() -> str:
    """Cycle through log levels: INFO -> VERBOSE -> DEBUG -> INFO.

    Returns:
        The new log level name

    Example:
        >>> toggle_log_level()  # INFO -> VERBOSE
        'VERBOSE'
        >>> toggle_log_level()  # VERBOSE -> DEBUG
        'DEBUG'
        >>> toggle_log_level()  # DEBUG -> INFO
        'INFO'
    """
    levels = [logging.INFO, VERBOSE, logging.DEBUG]
    logger = logging.getLogger("assassinate")
    current = logger.level

    try:
        idx = levels.index(current)
        new_level = levels[(idx + 1) % len(levels)]
    except ValueError:
        new_level = levels[0]

    set_level(logging.getLevelName(new_level))
    return logging.getLevelName(new_level)


def get_log_file() -> Path | None:
    """Get the current log file path, if any.

    Returns:
        Path to log file, or None if not logging to file
    """
    logger = logging.getLogger("assassinate")
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            return Path(handler.baseFilename)
    return None


def disable_console_logging() -> None:
    """Disable console (stderr) logging, keeping only file logging.

    Useful for scripts where you want logs only in a file.
    """
    for logger_name in ("assassinate", "msf"):
        logger = logging.getLogger(logger_name)
        logger.handlers = [
            h for h in logger.handlers
            if not isinstance(h, logging.StreamHandler)
            or isinstance(h, logging.FileHandler)
        ]


def enable_console_logging(level: str | None = None, colors: bool = True) -> None:
    """Re-enable console logging if it was disabled.

    Args:
        level: Optional level for console handler
        colors: Enable colored output
    """
    console_formatter = ColoredFormatter(use_colors=colors)

    for logger_name in ("assassinate", "msf"):
        logger = logging.getLogger(logger_name)

        # Check if already has a console handler
        has_console = any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
            for h in logger.handlers
        )

        if not has_console:
            if level:
                level_upper = level.upper()
                if level_upper == "VERBOSE":
                    log_level = VERBOSE
                elif level_upper == "SUCCESS":
                    log_level = SUCCESS
                else:
                    log_level = getattr(logging, level_upper, logger.level)
            else:
                log_level = logger.level

            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(log_level)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)


# =============================================================================
# Performance Logging
# =============================================================================

class PerformanceLogger:
    """Context manager for logging operation performance.

    Example:
        >>> with PerformanceLogger(logger, "exploit execution", target="192.168.1.1"):
        ...     result = exploit.run()
        # Logs: "exploit execution completed in 1234.56ms target=192.168.1.1"
    """

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

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        elapsed = (time.perf_counter() - self.start_time) * 1000  # ms

        if exc_type is not None:
            ctx = " ".join(f"{k}={v}" for k, v in self.context.items())
            self.logger.error(
                f"{self.operation} failed in {elapsed:.2f}ms {ctx} "
                f"error={exc_type.__name__}: {exc_val}".strip()
            )
        else:
            if self.logger.isEnabledFor(logging.DEBUG):
                ctx = " ".join(f"{k}={v}" for k, v in self.context.items())
                self.logger.debug(
                    f"{self.operation} completed in {elapsed:.2f}ms {ctx}".strip()
                )


# =============================================================================
# Auto-configuration
# =============================================================================

def _auto_configure() -> None:
    """Auto-configure logging from environment variables."""
    env_level = os.environ.get(ENV_LOG_LEVEL)
    env_file = os.environ.get(ENV_LOG_FILE)

    if env_level or env_file:
        setup_logging(level=env_level, log_file=env_file)


_auto_configure()
