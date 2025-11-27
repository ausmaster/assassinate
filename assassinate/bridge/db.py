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

    def report_service(self, **opts: str) -> int:
        """Report a service to the database.

        Args:
            **opts: Service options (host, port, proto, name, etc.).

        Returns:
            Service ID.

        Example:
            >>> db = fw.db()
            >>> svc_id = db.report_service(
            ...     host="192.168.1.100",
            ...     port="22",
            ...     proto="tcp",
            ...     name="ssh"
            ... )
            >>> print(f"Reported service with ID: {svc_id}")
        """
        return int(self._instance.report_service(opts))

    def report_vuln(self, **opts: str) -> int:
        """Report a vulnerability to the database.

        Args:
            **opts: Vulnerability options (host, name, refs, info, etc.).

        Returns:
            Vulnerability ID.

        Example:
            >>> db = fw.db()
            >>> vuln_id = db.report_vuln(
            ...     host="192.168.1.100",
            ...     name="CVE-2021-44228",
            ...     refs="CVE-2021-44228",
            ...     info="Log4Shell vulnerability"
            ... )
            >>> print(f"Reported vulnerability with ID: {vuln_id}")
        """
        return int(self._instance.report_vuln(opts))

    def report_cred(self, **opts: str) -> int:
        """Report a credential to the database.

        Args:
            **opts: Credential options (origin_type, address, port, username, etc.).

        Returns:
            Credential ID.

        Example:
            >>> db = fw.db()
            >>> cred_id = db.report_cred(
            ...     origin_type="service",
            ...     address="192.168.1.100",
            ...     port="22",
            ...     username="admin",
            ...     private_data="password123"
            ... )
            >>> print(f"Reported credential with ID: {cred_id}")
        """
        return int(self._instance.report_cred(opts))

    def vulns(self) -> list[str]:
        """Get all vulnerabilities from the database.

        Returns:
            List of vulnerabilities.

        Example:
            >>> db = fw.db()
            >>> vulns = db.vulns()
            >>> print(f"Found {len(vulns)} vulnerabilities")
        """
        return list(self._instance.vulns())

    def creds(self) -> list[str]:
        """Get all credentials from the database.

        Returns:
            List of credentials.

        Example:
            >>> db = fw.db()
            >>> creds = db.creds()
            >>> for cred in creds:
            ...     print(cred)
        """
        return list(self._instance.creds())

    def loot(self) -> list[str]:
        """Get all loot from the database.

        Returns:
            List of loot items.

        Example:
            >>> db = fw.db()
            >>> loot = db.loot()
            >>> print(f"Found {len(loot)} loot items")
        """
        return list(self._instance.loot())

    def __repr__(self) -> str:
        """Return string representation of DbManager.

        Returns:
            String representation.
        """
        return "<DbManager>"
