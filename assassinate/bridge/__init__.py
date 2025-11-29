"""Metasploit Framework bridge module via IPC.

This module provides Python wrappers that communicate with MSF via IPC
(Inter-Process Communication) using shared memory ring buffers.

Architecture:
    Python Client ↔ Shared Memory ↔ Rust Daemon ↔ Ruby FFI ↔ MSF

Public API:
    Functions:
        - initialize(msf_path): Initialize MSF connection (sync)
        - initialize_async(): Initialize MSF connection (async)
        - get_version(): Get MSF version

    Classes:
        - Framework: Main MSF interface
        - Module: MSF module (exploit/auxiliary/payload/etc.)
        - SessionManager: Manages active sessions
        - Session: Active session to compromised target

    Note: All Module methods are async. Use `await` when calling them.

Example:
    >>> from assassinate.bridge import initialize, Framework
    >>> import asyncio
    >>>
    >>> async def main():
    ...     from assassinate.bridge.core import initialize_async
    ...     await initialize_async()
    ...     fw = Framework()
    ...     print(fw.version())
    ...
    ...     # Create a module
    ...     mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
    ...     print(await mod.name())  # Module methods are async
    ...
    >>> asyncio.run(main())

Status:
    ✅ Core functionality (Framework, Module, Sessions) via IPC
    ✅ 38/38 tests passing - Full test suite passes!
    ⏳ DataStore, PayloadGenerator, DbManager, JobManager -
       to be implemented when needed
"""

from __future__ import annotations

from assassinate.bridge.core import (
    Framework,
    get_version,
    initialize,
    initialize_async,
)
from assassinate.bridge.modules import Module
from assassinate.bridge.sessions import Session, SessionManager

# These modules need IPC implementation - use direct module methods for now:
# - DataStore: Use module.set_option() / module.get_option() instead
# - PayloadGenerator: Use module.compatible_payloads() and
#   module.exploit()
# - DbManager: Database functionality to be implemented
# - JobManager: Job management to be implemented

__all__ = [
    "initialize",
    "initialize_async",
    "get_version",
    "Framework",
    "Module",
    "SessionManager",
    "Session",
]
