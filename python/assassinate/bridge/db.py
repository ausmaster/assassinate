"""MSF Database management.

Provides access to database operations for hosts, services,
vulnerabilities, etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from assassinate.bridge.client_utils import call_client_method

if TYPE_CHECKING:
    from assassinate.ipc.protocol import ClientProtocol


class DbManager:
    """Database manager for MSF.

    Provides access to hosts, services, vulnerabilities, credentials,
    and other database-stored information.

    Now uses IPC for all operations.
    """

    _client: ClientProtocol

    def __init__(self, client: ClientProtocol) -> None:
        """Initialize DbManager instance.

        Args:
            client: IPC client (MsfClient or SyncMsfClient) to use.

        Example:
            >>> from assassinate.ipc import MsfClient
            >>> client = MsfClient()
            >>> await client.connect()
            >>> db = DbManager(client)
        """
        self._client = client

    async def hosts(self) -> list[str]:
        """Get all hosts from the database.

        Returns:
            List of host IP addresses.

        Example:
            >>> db = DbManager(client)
            >>> hosts = await db.hosts()
            >>> print(f"Found {len(hosts)} hosts")
        """
        result = await call_client_method(self._client, "db_hosts")
        return list(result)

    async def services(self) -> list[str]:
        """Get all services from the database.

        Returns:
            List of services.

        Example:
            >>> db = DbManager(client)
            >>> services = await db.services()
            >>> for svc in services:
            ...     print(svc)
        """
        result = await call_client_method(self._client, "db_services")
        return list(result)

    async def report_host(self, **opts: str) -> int:
        """Report a host to the database.

        Args:
            **opts: Host options (host, os_name, os_flavor, etc.).

        Returns:
            Host ID.

        Example:
            >>> db = DbManager(client)
            >>> host_id = await db.report_host(
            ...     host="192.168.1.100",
            ...     os_name="Linux",
            ...     os_flavor="Ubuntu"
            ... )
            >>> print(f"Reported host with ID: {host_id}")
        """
        result = await call_client_method(self._client, "db_report_host", opts)
        return int(result)

    async def report_service(self, **opts: str) -> int:
        """Report a service to the database.

        Args:
            **opts: Service options (host, port, proto, name, etc.).

        Returns:
            Service ID.

        Example:
            >>> db = DbManager(client)
            >>> svc_id = await db.report_service(
            ...     host="192.168.1.100",
            ...     port="22",
            ...     proto="tcp",
            ...     name="ssh"
            ... )
            >>> print(f"Reported service with ID: {svc_id}")
        """
        result = await call_client_method(
            self._client, "db_report_service", opts
        )
        return int(result)

    async def report_vuln(self, **opts: str) -> int:
        """Report a vulnerability to the database.

        Args:
            **opts: Vulnerability options (host, name, refs, info,
                    etc.).

        Returns:
            Vulnerability ID.

        Example:
            >>> db = DbManager(client)
            >>> vuln_id = await db.report_vuln(
            ...     host="192.168.1.100",
            ...     name="CVE-2021-44228",
            ...     refs="CVE-2021-44228",
            ...     info="Log4Shell vulnerability"
            ... )
            >>> print(f"Reported vulnerability with ID: {vuln_id}")
        """
        result = await call_client_method(self._client, "db_report_vuln", opts)
        return int(result)

    async def report_cred(self, **opts: str) -> int:
        """Report a credential to the database.

        Args:
            **opts: Credential options (origin_type, address, port,
                    username, etc.).

        Returns:
            Credential ID.

        Example:
            >>> db = DbManager(client)
            >>> cred_id = await db.report_cred(
            ...     origin_type="service",
            ...     address="192.168.1.100",
            ...     port="22",
            ...     username="admin",
            ...     private_data="password123"
            ... )
            >>> print(f"Reported credential with ID: {cred_id}")
        """
        result = await call_client_method(self._client, "db_report_cred", opts)
        return int(result)

    async def vulns(self) -> list[str]:
        """Get all vulnerabilities from the database.

        Returns:
            List of vulnerabilities.

        Example:
            >>> db = DbManager(client)
            >>> vulns = await db.vulns()
            >>> print(f"Found {len(vulns)} vulnerabilities")
        """
        result = await call_client_method(self._client, "db_vulns")
        return list(result)

    async def creds(self) -> list[str]:
        """Get all credentials from the database.

        Returns:
            List of credentials.

        Example:
            >>> db = DbManager(client)
            >>> creds = await db.creds()
            >>> for cred in creds:
            ...     print(cred)
        """
        result = await call_client_method(self._client, "db_creds")
        return list(result)

    async def loot(self) -> list[str]:
        """Get all loot from the database.

        Returns:
            List of loot items.

        Example:
            >>> db = DbManager(client)
            >>> loot = await db.loot()
            >>> print(f"Found {len(loot)} loot items")
        """
        result = await call_client_method(self._client, "db_loot")
        return list(result)

    def __repr__(self) -> str:
        """Return string representation of DbManager.

        Returns:
            String representation.
        """
        return "<DbManager>"
