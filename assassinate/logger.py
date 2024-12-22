"""Logging configuration for Metasploit Core Python bindings.

This module provides logger setup, configuration, and management utilities
to ensure consistent logging across the Python codebase.
"""

from __future__ import annotations

import logging
from typing import Optional


def setup_logger(
    name: str, level: int = logging.INFO, file: Optional[str] = None
) -> logging.Logger:
    """Set up a logger for the application.

    This function initializes a logger with a specific name and log level.
    Optionally, logs can also be written to a file.

    :param name: The name of the logger.
    :type name: str
    :param level: The logging level (e.g., logging.DEBUG, logging.INFO).
    :type level: int
    :param file: Optional file path for logging output.
    :type file: Optional[str]

    :return: Configured logger instance.
    :rtype: logging.Logger

    :Example:

        >>> from logger import setup_logger
        >>> logger = setup_logger("MetasploitLogger", logging.DEBUG)
        >>> logger.info("This is an info message.")

    .. note::
        By default, logs are output to the console unless a file is specified.

    .. seealso:: :mod:`logging`
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if not logger.handlers:
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File Handler (optional)
        if file:
            file_handler = logging.FileHandler(file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Retrieve an existing logger by name.

    :param name: The name of the logger.
    :type name: str

    :return: Logger instance.
    :rtype: logging.Logger

    :Example:

        >>> from logger import get_logger
        >>> logger = get_logger("MetasploitLogger")
        >>> logger.debug("Debugging message.")

    .. seealso:: :func:`setup_logger`
    """
    return logging.getLogger(name)


def set_logger_level(logger: logging.Logger, level: int) -> None:
    """Set the logging level for an existing logger.

    :param logger: The logger instance.
    :type logger: logging.Logger
    :param level: The desired logging level
    (e.g., logging.DEBUG, logging.INFO).
    :type level: int

    :Example:

        >>> from logger import set_logger_level, setup_logger
        >>> logger = setup_logger("MetasploitLogger")
        >>> set_logger_level(logger, logging.ERROR)

    .. seealso:: :func:`setup_logger`
    """
    logger.setLevel(level)
