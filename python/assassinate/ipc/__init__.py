"""IPC client for high-performance Metasploit Framework communication.

This module provides an ultra-low-latency IPC layer for communicating with the
Metasploit Framework through a Rust daemon. The IPC layer uses:

- Shared memory for zero-copy communication
- Lock-free ring buffers for <100ns operations
- Cap'n Proto for zero-copy serialization
- Async I/O for non-blocking operations

Performance target: <5μs round-trip latency

Example:
    Basic usage::

        import asyncio
        from assassinate.ipc import MsfClient

        async def main():
            # Connect to daemon
            async with MsfClient() as client:
                # Get MSF version
                version = await client.framework_version()
                print(f"MSF Version: {version}")

                # Search for exploits
                results = await client.search("type:exploit platform:linux")
                print(f"Found {len(results)} exploits")

        asyncio.run(main())
"""

from __future__ import annotations

__all__ = ["MsfClient", "IpcError"]

from assassinate.ipc.client import MsfClient
from assassinate.ipc.errors import IpcError
