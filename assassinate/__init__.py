"""Assassinate - Metasploit Framework Python interface.

A modular exploitation framework providing Python access to the complete
Metasploit Framework through a high-performance IPC architecture.

This package provides:

1. **Sync API** (``assassinate.bridge``):
   Synchronous interface for traditional Python code. Uses a background
   thread to handle async operations transparently.

2. **Async API** (``assassinate.bridge.async_api``):
   Native async/await interface for async Python code. Provides best
   performance when used in async contexts.

Example (Sync):
    Using the synchronous API::

        from assassinate.bridge import initialize, Framework

        # Connect to MSF daemon
        initialize()

        # Create framework and list exploits
        fw = Framework()
        exploits = fw.list_modules("exploit")
        print(f"Available exploits: {len(exploits)}")

Example (Async):
    Using the async API::

        from assassinate.bridge.async_api import initialize, AsyncFramework

        # Connect to MSF daemon
        await initialize()

        # Create framework and list exploits
        fw = AsyncFramework()
        exploits = await fw.list_modules("exploit")
        print(f"Available exploits: {len(exploits)}")

Attributes:
    __version__: Package version string.

Note:
    Requires the assassinate daemon to be running. The daemon uses a Rust
    FFI bridge to communicate with Metasploit Framework via shared memory IPC.
    See README.md for daemon setup instructions.
"""

from __future__ import annotations

import os

__version__ = "0.1.0"
__all__ = ["bridge", "setup_logging"]

# Re-export bridge module for easy access
from assassinate import bridge

# Setup logging with default configuration
# Can be overridden by calling setup_logging() with custom parameters
from assassinate.logging import setup_logging

# Setup default logging based on environment variables
log_level = os.getenv("ASSASSINATE_LOG_LEVEL", "WARNING")
log_file = os.getenv("ASSASSINATE_LOG_FILE", None)
setup_logging(level=log_level, log_file=log_file, structured=True)

# Note: High-level API will be added here in future versions
