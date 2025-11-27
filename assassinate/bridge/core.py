"""Core Metasploit Framework functionality.

Provides framework initialization and the main Framework class for
interacting with MSF via IPC.

Note: This module now uses IPC to communicate with the MSF daemon.
      Make sure the assassinate_daemon is running before using this API.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from assassinate.ipc import MsfClient

if TYPE_CHECKING:
    from assassinate.bridge.datastore import DataStore
    from assassinate.bridge.db import DbManager
    from assassinate.bridge.jobs import JobManager
    from assassinate.bridge.modules import Module
    from assassinate.bridge.payloads import PayloadGenerator
    from assassinate.bridge.sessions import SessionManager

# Global IPC client - initialized on first use
_client: MsfClient | None = None


def _get_client() -> MsfClient:
    """Get or create the global IPC client."""
    global _client
    if _client is None:
        _client = MsfClient()
        # Connect synchronously
        asyncio.run(_client.connect())
    return _client


def _run_async(coro):
    """Helper to run async code synchronously."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If event loop is already running, we need to use a different approach
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(coro)


def initialize(msf_path: str | None = None) -> None:
    """Initialize connection to the Metasploit Framework daemon.

    Note: With IPC architecture, this just establishes the connection to the daemon.
          The daemon itself must be started separately with the MSF path.

    Args:
        msf_path: Deprecated - MSF path is configured in the daemon.
                  Kept for API compatibility.

    Raises:
        RuntimeError: If connection to daemon fails.

    Example:
        >>> initialize()  # Connect to running daemon
    """
    _get_client()


def get_version() -> str:
    """Get Metasploit Framework version string.

    Returns:
        MSF version (e.g., "6.4.28-dev").

    Raises:
        RuntimeError: If MSF is not initialized or version cannot be determined.

    Example:
        >>> version = get_version()
        >>> print(f"MSF Version: {version}")
        MSF Version: 6.4.28-dev
    """
    client = _get_client()
    result = _run_async(client.framework_version())
    return result.get("version", "unknown")


class Framework:
    """Metasploit Framework instance.

    Provides access to modules, sessions, datastores, and payload generation.
    This is the main entry point for interacting with MSF via IPC.

    Note:
        Requires initialize() to be called first to connect to the daemon.

    Example:
        >>> fw = Framework()
        >>> print(fw.version())
        6.4.28-dev
    """

    _client: MsfClient

    def __init__(self) -> None:
        """Initialize Framework instance.

        Raises:
            RuntimeError: If daemon connection fails.

        Example:
            >>> fw = Framework()
        """
        self._client = _get_client()

    def version(self) -> str:
        """Get MSF version.

        Returns:
            Version string (e.g., "6.4.28-dev").

        Example:
            >>> fw = Framework()
            >>> print(fw.version())
            6.4.28-dev
        """
        result = _run_async(self._client.framework_version())
        return result.get("version", "unknown")

    def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list. Valid values:
                "exploit", "auxiliary", "payload", "encoder", "nop", "post".

        Returns:
            List of module names (e.g., ["exploit/unix/ftp/vsftpd_234_backdoor"]).

        Raises:
            ValueError: If module_type is invalid.
            RuntimeError: If listing fails.

        Example:
            >>> fw = Framework()
            >>> exploits = fw.list_modules("exploit")
            >>> print(f"Found {len(exploits)} exploits")
            Found 2575 exploits
        """
        return _run_async(self._client.list_modules(module_type))

    def create_module(self, module_name: str) -> Module:
        """Create a module instance by name.

        Args:
            module_name: Full module name (e.g., "exploit/unix/ftp/vsftpd_234_backdoor").

        Returns:
            Module instance.

        Raises:
            ValueError: If module_name is invalid or module doesn't exist.
            RuntimeError: If module creation fails.

        Example:
            >>> fw = Framework()
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> print(mod.name())
            vsftpd_234_backdoor
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.modules import Module

        module_info = _run_async(self._client.get_module_info(module_name))
        return Module(module_name, module_info, self._client)

    def datastore(self) -> DataStore:
        """Get framework global datastore.

        The global datastore contains framework-wide configuration options.

        Returns:
            Global DataStore instance.

        Example:
            >>> fw = Framework()
            >>> ds = fw.datastore()
            >>> ds.set("WORKSPACE", "default")
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.datastore import DataStore

        return DataStore(self._client)

    def sessions(self) -> SessionManager:
        """Get session manager.

        Returns:
            SessionManager instance for managing active sessions.

        Example:
            >>> fw = Framework()
            >>> sm = fw.sessions()
            >>> session_ids = sm.list()
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.sessions import SessionManager

        return SessionManager(self._client)

    def payload_generator(self) -> PayloadGenerator:
        """Get payload generator.

        Returns:
            PayloadGenerator instance for creating payloads.

        Example:
            >>> fw = Framework()
            >>> pg = fw.payload_generator()
            >>> payloads = pg.list_payloads()
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.payloads import PayloadGenerator

        return PayloadGenerator(self._client)

    def db(self) -> DbManager:
        """Get database manager.

        Returns:
            DbManager instance for database operations.

        Example:
            >>> fw = Framework()
            >>> db = fw.db()
            >>> hosts = db.hosts()
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.db import DbManager

        return DbManager(self._client)

    def search(self, query: str) -> list[str]:
        """Search for modules by keyword, CVE, name, etc.

        Args:
            query: Search query string.

        Returns:
            List of matching module names.

        Example:
            >>> fw = Framework()
            >>> results = fw.search("vsftpd")
            >>> for module in results:
            ...     print(module)
            exploit/unix/ftp/vsftpd_234_backdoor
        """
        return _run_async(self._client.search(query))

    def jobs(self) -> JobManager:
        """Get jobs manager.

        Returns:
            JobManager instance for managing background jobs.

        Example:
            >>> fw = Framework()
            >>> jm = fw.jobs()
            >>> job_ids = jm.list()
        """
        # Import here to avoid circular dependency
        from assassinate.bridge.jobs import JobManager

        return JobManager(self._client)

    def threads(self) -> int:
        """Get framework threads configuration.

        Returns:
            Number of threads configured for the framework.

        Example:
            >>> fw = Framework()
            >>> num_threads = fw.threads()
            >>> print(f"Framework threads: {num_threads}")
        """
        return _run_async(self._client.threads())

    def threads_enabled(self) -> bool:
        """Check if framework has threads configured.

        Returns:
            True if threads are enabled, False otherwise.

        Example:
            >>> fw = Framework()
            >>> if fw.threads_enabled():
            ...     print("Threading is enabled")
        """
        # For IPC, assume threads are enabled if we can get a thread count
        threads = _run_async(self._client.threads())
        return threads > 0

    def __repr__(self) -> str:
        """Return string representation of Framework.

        Returns:
            String representation.
        """
        return f"<Framework version={self.version()}>"
