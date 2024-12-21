from __future__ import annotations

"""
Assassinate Python Interface Package.

This package provides Python bindings for the Metasploit Core shared library
and offers both synchronous and asynchronous APIs for interacting with Metasploit Core.
"""

from .core import MetasploitCore
from .exceptions import InitializationError, RPCError, ValidationError
from .logger import logger
from .utils import validate_json
