"""Metasploit Framework bridge module via IPC.

This module provides Python wrappers that communicate with MSF via IPC
(Inter-Process Communication) using shared memory ring buffers.

Architecture:
    Python Client ↔ Shared Memory ↔ Rust Daemon ↔ Ruby FFI ↔ MSF

There are TWO distinct APIs:

1. **Sync API** (default) - For synchronous code:
   ```python
   from assassinate.bridge import initialize, Framework, get_version

   initialize()  # Connect to daemon
   version = get_version()

   fw = Framework()
   print(fw.version())
   ```

2. **Async API** - For async code:
   ```python
   from assassinate.bridge.async_api import (
       initialize,
       AsyncFramework,
       get_version,
   )

   await initialize()  # Connect to daemon
   version = await get_version()

   fw = AsyncFramework()
   await fw.initialize()
   print(await fw.version())
   ```

The sync API uses a background thread to run async operations, making it
convenient for use in synchronous code without managing event loops.

Public API (Sync):
    Functions:
        - initialize(msf_path): Initialize MSF connection
        - get_version(): Get MSF version

    Classes:
        - Framework: Main MSF interface
        - Module: MSF module (exploit/auxiliary/payload/etc.)
        - SessionManager: Manages active sessions
        - Session: Active session to compromised target

Public API (Async):
    Available via `assassinate.bridge.async_api`

    Functions:
        - initialize(): Initialize MSF connection (async)
        - get_version(): Get MSF version (async)

    Classes:
        - AsyncFramework: Main MSF interface (async)

Status:
    ✅ Core functionality (Framework, Module, Sessions) via IPC
    ✅ 118/118 integration tests passing
    ✅ Sync and Async APIs cleanly separated
"""

from __future__ import annotations

from assassinate.bridge.modules import Module
from assassinate.bridge.sessions import Session, SessionManager

# Default export: Sync API
from assassinate.bridge.sync_api import (
    Framework,
    get_version,
    initialize,
)

__all__ = [
    "initialize",
    "get_version",
    "Framework",
    "Module",
    "SessionManager",
    "Session",
]
