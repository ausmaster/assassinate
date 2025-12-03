"""Sync API for Metasploit Framework via IPC.

This module provides synchronous access to MSF through the IPC daemon
using a background thread to run the async event loop.

Use this when you're in synchronous code and don't want to manage async/await.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from assassinate.ipc.sync import SyncMsfClient

if TYPE_CHECKING:
    from assassinate.bridge.datastore import DataStore
    from assassinate.bridge.db import DbManager
    from assassinate.bridge.jobs import JobManager
    from assassinate.bridge.modules import Module
    from assassinate.bridge.payloads import PayloadGenerator
    from assassinate.bridge.sessions import SessionManager

# Global sync client - initialized on first use
_client: SyncMsfClient | None = None


def get_client() -> SyncMsfClient:
    """Get or create the global sync IPC client."""
    global _client
    if _client is None:
        _client = SyncMsfClient()
        _client.connect()
    return _client


def initialize(msf_path: str | None = None) -> None:
    """Initialize connection to the Metasploit Framework daemon.

    Sync version - uses a background thread to run the event loop.

    Args:
        msf_path: Deprecated - MSF path is configured in the daemon.
                  Kept for API compatibility.

    Raises:
        RuntimeError: If connection to daemon fails.

    Example:
        >>> initialize()  # Connect to running daemon
    """
    get_client()


def get_version() -> str:
    """Get Metasploit Framework version string.

    Returns:
        MSF version (e.g., "6.4.28-dev").

    Example:
        >>> version = get_version()
        >>> print(f"MSF Version: {version}")
    """
    client = get_client()
    result = client.framework_version()
    return result.get("version", "unknown")


class Framework:
    """Synchronous Metasploit Framework instance.

    Provides sync access to core framework operations. Uses a background
    thread to run async operations transparently.

    Note: For advanced usage with Module, Session, and other objects that
          have async methods, use the async API (AsyncFramework) instead.
          This sync API is best for simple queries and searches.

    Example:
        >>> fw = Framework()
        >>> print(fw.version())
        >>> exploits = fw.list_modules("exploit")
        >>> results = fw.search("vsftpd")
    """

    _client: SyncMsfClient

    def __init__(self) -> None:
        """Initialize Framework instance.

        The client connects automatically on first use.
        """
        self._client = get_client()

    def version(self) -> str:
        """Get MSF version.

        Returns:
            Version string (e.g., "6.4.28-dev").
        """
        result = self._client.framework_version()
        return result.get("version", "unknown")

    def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list (exploit, auxiliary, etc.)

        Returns:
            List of module names.
        """
        return self._client.list_modules(module_type)

    def create_module(self, module_name: str) -> Module:
        """Create a module instance by name.

        Note: Module methods are async, so you need to use await even
              with the sync Framework. This is because Module objects
              work with both sync and async clients transparently.

        Args:
            module_name: Full module name.

        Returns:
            Module instance (use await on its methods).

        Example:
            >>> import asyncio
            >>> fw = Framework()
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> # Module methods are async - use await
            >>> name = asyncio.run(mod.name())
        """
        from assassinate.bridge.modules import Module

        module_id = self._client.create_module(module_name)
        return Module(module_id, self._client)

    def get_client(self) -> SyncMsfClient:
        """Get the underlying sync client for advanced usage.

        Returns:
            SyncMsfClient instance for direct method calls.
        """
        return self._client

    def datastore(self) -> DataStore:
        """Get framework global datastore.

        Returns:
            Global DataStore instance.
        """
        from assassinate.bridge.datastore import DataStore

        return DataStore(self._client)

    def sessions(self) -> SessionManager:
        """Get session manager.

        Returns:
            SessionManager instance.
        """
        from assassinate.bridge.sessions import SessionManager

        return SessionManager(self._client)

    def payload_generator(self) -> PayloadGenerator:
        """Get payload generator.

        Returns:
            PayloadGenerator instance.
        """
        from assassinate.bridge.payloads import PayloadGenerator

        return PayloadGenerator(self._client)

    def db(self) -> DbManager:
        """Get database manager.

        Returns:
            DbManager instance.
        """
        from assassinate.bridge.db import DbManager

        return DbManager(self._client)

    def search(self, query: str) -> list[str]:
        """Search for modules.

        Args:
            query: Search query string.

        Returns:
            List of matching module names.
        """
        return self._client.search(query)

    def jobs(self) -> JobManager:
        """Get jobs manager.

        Returns:
            JobManager instance.
        """
        from assassinate.bridge.jobs import JobManager

        return JobManager(self._client)

    def threads(self) -> int:
        """Get framework threads configuration.

        Returns:
            Number of threads configured.
        """
        return self._client.threads()

    def threads_enabled(self) -> bool:
        """Check if framework has threads configured.

        Returns:
            True if threads are enabled.
        """
        threads = self._client.threads()
        return threads > 0

    def __repr__(self) -> str:
        """Return string representation."""
        try:
            version = self.version()
            return f"<Framework version={version}>"
        except Exception:
            return "<Framework>"
