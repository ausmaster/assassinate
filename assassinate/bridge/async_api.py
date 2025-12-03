"""Async API for Metasploit Framework via IPC.

This module provides async-first access to MSF through the IPC daemon.
Use this when you're already in an async context.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from assassinate.ipc import MsfClient

if TYPE_CHECKING:
    from assassinate.bridge.datastore import DataStore
    from assassinate.bridge.db import DbManager
    from assassinate.bridge.jobs import JobManager
    from assassinate.bridge.modules import Module
    from assassinate.bridge.payloads import PayloadGenerator
    from assassinate.bridge.sessions import SessionManager

# Global async client - initialized on first use
_client: MsfClient | None = None


async def get_client() -> MsfClient:
    """Get or create the global async IPC client."""
    global _client
    if _client is None:
        _client = MsfClient()
        await _client.connect()
    return _client


async def initialize(msf_path: str | None = None) -> None:
    """Initialize connection to the Metasploit Framework daemon.

    Args:
        msf_path: Deprecated - MSF path is configured in the daemon.
                  Kept for API compatibility.

    Raises:
        RuntimeError: If connection to daemon fails.

    Example:
        >>> await initialize()  # Connect to running daemon
    """
    await get_client()


async def get_version() -> str:
    """Get Metasploit Framework version string.

    Returns:
        MSF version (e.g., "6.4.28-dev").

    Example:
        >>> version = await get_version()
        >>> print(f"MSF Version: {version}")
    """
    client = await get_client()
    result = await client.framework_version()
    return result.get("version", "unknown")


class AsyncFramework:
    """Async Metasploit Framework instance.

    Provides async access to modules, sessions, datastores, and payload
    generation.

    Example:
        >>> fw = AsyncFramework()
        >>> await fw.initialize()
        >>> print(await fw.version())
    """

    _client: MsfClient | None

    def __init__(self) -> None:
        """Initialize Framework instance.

        Note: Call initialize() before using other methods.
        """
        self._client = None

    async def initialize(self) -> None:
        """Initialize the framework connection."""
        self._client = await get_client()

    def _ensure_initialized(self) -> MsfClient:
        """Ensure framework is initialized."""
        if self._client is None:
            raise RuntimeError(
                "Framework not initialized. Call await fw.initialize() first."
            )
        return self._client

    async def version(self) -> str:
        """Get MSF version.

        Returns:
            Version string (e.g., "6.4.28-dev").
        """
        client = self._ensure_initialized()
        result = await client.framework_version()
        return result.get("version", "unknown")

    async def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list (exploit, auxiliary, etc.)

        Returns:
            List of module names.
        """
        client = self._ensure_initialized()
        return await client.list_modules(module_type)

    async def create_module(self, module_name: str) -> Module:
        """Create a module instance by name.

        Args:
            module_name: Full module name.

        Returns:
            Module instance.
        """
        from assassinate.bridge.modules import Module

        client = self._ensure_initialized()
        module_id = await client.create_module(module_name)
        return Module(module_id, client)

    def datastore(self) -> DataStore:
        """Get framework global datastore.

        Returns:
            Global DataStore instance.
        """
        from assassinate.bridge.datastore import DataStore

        client = self._ensure_initialized()
        return DataStore(client)

    def sessions(self) -> SessionManager:
        """Get session manager.

        Returns:
            SessionManager instance.
        """
        from assassinate.bridge.sessions import SessionManager

        client = self._ensure_initialized()
        return SessionManager(client)

    def payload_generator(self) -> PayloadGenerator:
        """Get payload generator.

        Returns:
            PayloadGenerator instance.
        """
        from assassinate.bridge.payloads import PayloadGenerator

        client = self._ensure_initialized()
        return PayloadGenerator(client)

    def db(self) -> DbManager:
        """Get database manager.

        Returns:
            DbManager instance.
        """
        from assassinate.bridge.db import DbManager

        client = self._ensure_initialized()
        return DbManager(client)

    async def search(self, query: str) -> list[str]:
        """Search for modules.

        Args:
            query: Search query string.

        Returns:
            List of matching module names.
        """
        client = self._ensure_initialized()
        return await client.search(query)

    def jobs(self) -> JobManager:
        """Get jobs manager.

        Returns:
            JobManager instance.
        """
        from assassinate.bridge.jobs import JobManager

        client = self._ensure_initialized()
        return JobManager(client)

    async def threads(self) -> int:
        """Get framework threads configuration.

        Returns:
            Number of threads configured.
        """
        client = self._ensure_initialized()
        return await client.threads()

    async def threads_enabled(self) -> bool:
        """Check if framework has threads configured.

        Returns:
            True if threads are enabled.
        """
        threads = await self.threads()
        return threads > 0

    def __repr__(self) -> str:
        """Return string representation."""
        return "<AsyncFramework>"
