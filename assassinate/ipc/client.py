"""High-performance IPC client for Metasploit Framework."""

from __future__ import annotations

import asyncio
from typing import Any

from assassinate.ipc.errors import BufferEmptyError, RemoteError, TimeoutError
from assassinate.ipc.protocol import deserialize_response, serialize_call
from assassinate.ipc.shm import RingBuffer


class MsfClient:
    """Async client for communicating with MSF daemon via IPC.

    This client provides a high-level async interface to the MSF daemon,
    handling all IPC details internally.

    Example:
        async with MsfClient() as client:
            version = await client.framework_version()
            print(f"MSF Version: {version}")
    """

    DEFAULT_SHM_NAME = "/assassinate_msf_ipc"
    DEFAULT_BUFFER_SIZE = 64 * 1024 * 1024  # 64 MB

    def __init__(self, shm_name: str = DEFAULT_SHM_NAME, buffer_size: int = DEFAULT_BUFFER_SIZE):
        """Initialize the IPC client.

        Args:
            shm_name: Shared memory name (must match daemon)
            buffer_size: Ring buffer size (must match daemon)
        """
        self.shm_name = shm_name
        self.buffer_size = buffer_size
        self.ring_buffer: RingBuffer | None = None
        self.next_call_id = 1
        self._pending_calls: dict[int, asyncio.Future] = {}

    async def connect(self) -> None:
        """Connect to the daemon's shared memory."""
        self.ring_buffer = RingBuffer(self.shm_name, self.buffer_size)

    async def disconnect(self) -> None:
        """Disconnect from shared memory."""
        if self.ring_buffer:
            self.ring_buffer.close()
            self.ring_buffer = None

    async def __aenter__(self) -> MsfClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def _call(self, method: str, *args: Any, timeout: float = 5.0) -> Any:
        """Make an RPC call to the daemon.

        Args:
            method: Method name to call
            *args: Method arguments
            timeout: Timeout in seconds

        Returns:
            Method result

        Raises:
            TimeoutError: If call times out
            RemoteError: If daemon returns an error
        """
        if not self.ring_buffer:
            raise RuntimeError("Not connected - call connect() first")

        # Generate call ID
        call_id = self.next_call_id
        self.next_call_id += 1

        # Serialize and send request
        request_bytes = serialize_call(call_id, method, list(args))
        self.ring_buffer.try_write(request_bytes)

        # Wait for response with timeout
        start_time = asyncio.get_event_loop().time()
        while True:
            try:
                # Try to read response
                response_bytes = self.ring_buffer.try_read()
                response_call_id, result, error = deserialize_response(response_bytes)

                # Check if this is our response
                if response_call_id == call_id:
                    if error:
                        raise RemoteError(error["code"], error["message"])
                    return result

                # Not our response - put it back? For now just skip
                # In a real implementation we'd need a queue of responses

            except BufferEmptyError:
                # No data yet - check timeout
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed > timeout:
                    raise TimeoutError(f"Call to {method} timed out after {timeout}s")

                # Sleep briefly and retry
                await asyncio.sleep(0.001)  # 1ms

    # MSF API Methods

    async def framework_version(self) -> dict[str, str]:
        """Get the MSF framework version.

        Returns:
            Dictionary with version information
        """
        return await self._call("framework_version")

    async def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list (exploit, auxiliary, post, etc.)

        Returns:
            List of module names
        """
        result = await self._call("list_modules", module_type)
        return result.get("modules", [])

    async def search(self, query: str) -> list[str]:
        """Search for modules matching a query.

        Args:
            query: Search query string

        Returns:
            List of matching module names
        """
        result = await self._call("search", query)
        return result.get("results", [])

    async def get_module_info(self, module_name: str) -> dict[str, Any]:
        """Get detailed information about a module.

        Args:
            module_name: Full module name

        Returns:
            Dictionary with module information
        """
        return await self._call("get_module_info", module_name)

    async def threads(self) -> int:
        """Get the framework thread count.

        Returns:
            Number of threads
        """
        result = await self._call("threads")
        return result.get("threads", 0)

    async def list_sessions(self) -> list[int]:
        """List all active session IDs.

        Returns:
            List of session IDs
        """
        result = await self._call("list_sessions")
        return result.get("session_ids", [])
