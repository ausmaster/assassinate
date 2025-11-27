"""MSF Database management.

Provides access to database operations for hosts, services, vulnerabilities, etc.
"""

from __future__ import annotations

from typing import Any


class DbManager:
    """Database manager for MSF.

    Provides access to hosts, services, vulnerabilities, credentials,
    and other database-stored information.
    """

    _instance: Any  # The underlying PyO3 DbManager instance

    def __init__(self, instance: Any) -> None:
        """Initialize DbManager wrapper.

        Args:
            instance: PyO3 DbManager instance.

        Note:
            This is called internally via Framework.db().
        """
        self._instance = instance

    def hosts(self) -> list[str]:
        """Get all hosts from the database.

        Returns:
            List of host IP addresses.

        Example:
            >>> db = fw.db()
            >>> hosts = db.hosts()
            >>> print(f"Found {len(hosts)} hosts")
        """
        return list(self._instance.hosts())

    def services(self) -> list[str]:
        """Get all services from the database.

        Returns:
            List of services.

        Example:
            >>> db = fw.db()
            >>> services = db.services()
            >>> for svc in services:
            ...     print(svc)
        """
        return list(self._instance.services())

    def report_host(self, **opts: str) -> int:
        """Report a host to the database.

        Args:
            **opts: Host options (host, os_name, os_flavor, etc.).

        Returns:
            Host ID.

        Example:
            >>> db = fw.db()
            >>> host_id = db.report_host(
            ...     host="192.168.1.100",
            ...     os_name="Linux",
            ...     os_flavor="Ubuntu"
            ... )
            >>> print(f"Reported host with ID: {host_id}")
        """
        return int(self._instance.report_host(opts))

    def __repr__(self) -> str:
        """Return string representation of DbManager.

        Returns:
            String representation.
        """
        return "<DbManager>"
