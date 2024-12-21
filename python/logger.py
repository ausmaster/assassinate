from __future__ import annotations
from logging import Logger, getLogger, StreamHandler, Formatter


def get_logger(name: str, level: str = "INFO") -> Logger:
    """
    Create and configure a logger.

    :param name: Logger name.
    :param level: Logging level (DEBUG, INFO, WARN, ERROR).
    :return: Configured logger instance.
    """
    logger = getLogger(name)
    logger.setLevel(level.upper())

    handler = StreamHandler()
    formatter = Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger


logger = get_logger("assassinate")
