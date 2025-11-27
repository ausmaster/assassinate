"""Core Metasploit Framework functionality.

Provides framework initialization and the main Framework class for
interacting with MSF.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from assassinate.bridge.datastore import DataStore
    from assassinate.bridge.db import DbManager
    from assassinate.bridge.jobs import JobManager
    from assassinate.bridge.modules import Module
    from assassinate.bridge.payloads import PayloadGenerator
    from assassinate.bridge.sessions import SessionManager

try:
    import assassinate_bridge as _bridge  # type: ignore[import-not-found]
except ImportError as e:
    msg = (
        "assassinate_bridge Rust module not found. "
        "Please compile the Rust bridge first:\n"
        "  cd assassinate_bridge && cargo build --release"
    )
    raise ImportError(msg) from e


def initialize(msf_path: str) -> None:
    """Initialize the Metasploit Framework.

    Must be called before any other MSF operations. This loads the Ruby VM
    and initializes the MSF environment.

    Args:
        msf_path: Path to Metasploit Framework installation directory
            (e.g., "/opt/metasploit-framework").

    Raises:
        RuntimeError: If initialization fails (invalid path, missing deps, etc.).

    Example:
        >>> initialize("/opt/metasploit-framework")
    """
    _bridge.initialize_metasploit(msf_path)  # type: ignore[attr-defined]


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
    return str(_bridge.get_version())  # type: ignore[attr-defined]


class Framework:
    """Metasploit Framework instance.

    Provides access to modules, sessions, datastores, and payload generation.
    This is the main entry point for interacting with MSF.

    Note:
        Requires initialize() to be called first.

    Example:
        >>> fw = Framework()
        >>> print(fw.version())
        6.4.28-dev
    """

    _instance: Any  # The underlying PyO3 Framework instance

    def __init__(self) -> None:
        """Initialize Framework instance.

        Raises:
            RuntimeError: If MSF is not initialized or framework creation fails.

        Example:
            >>> fw = Framework()
        """
        self._instance = _bridge.Framework()  # type: ignore[attr-defined]

    def version(self) -> str:
        """Get MSF version.

        Returns:
            Version string (e.g., "6.4.28-dev").

        Example:
            >>> fw = Framework()
            >>> print(fw.version())
            6.4.28-dev
        """
        return str(self._instance.version())

    def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list. Valid values:
                "exploits", "auxiliary", "payloads", "encoders", "nops", "post".

        Returns:
            List of module names (e.g., ["exploit/unix/ftp/vsftpd_234_backdoor"]).

        Raises:
            ValueError: If module_type is invalid.
            RuntimeError: If listing fails.

        Example:
            >>> fw = Framework()
            >>> exploits = fw.list_modules("exploits")
            >>> print(f"Found {len(exploits)} exploits")
            Found 2575 exploits
        """
        return list(self._instance.list_modules(module_type))

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

        instance = self._instance.create_module(module_name)
        return Module(instance)

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

        return DataStore(self._instance.datastore())

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

        return SessionManager(self._instance.sessions())

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

        return PayloadGenerator(self)

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

        return DbManager(self._instance.db())

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
        return list(self._instance.search(query))

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

        return JobManager(self._instance.jobs())

    def __repr__(self) -> str:
        """Return string representation of Framework.

        Returns:
            String representation.
        """
        return f"<Framework version={self.version()}>"
