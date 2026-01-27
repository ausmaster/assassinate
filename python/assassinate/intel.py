"""Intel module - Intelligence layer for credential and host tracking.

Provides a clean API over the msf.db_* functions for managing
hosts, services, credentials, and vulnerabilities discovered
during an engagement.

Example:
    >>> intel = hideout.intel
    >>>
    >>> # Store credentials found during exploitation
    >>> intel.store_cred("192.168.1.100", 22, "root", "password123", service="ssh")
    >>>
    >>> # Query stored data
    >>> for cred in intel.creds(host="192.168.1.100"):
    ...     print(f"{cred['user']}:{cred['pass']}")
    >>>
    >>> # Get all discovered hosts
    >>> for host in intel.hosts():
    ...     print(f"{host['address']} - {host['os_name']}")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from assassinate.log_config import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger("intel")


class Intel:
    """Intelligence layer for tracking hosts, services, and credentials.

    Wraps the low-level msf.db_* functions with a cleaner API focused
    on the most common intelligence gathering operations.

    Note:
        Database operations require MSF database to be connected.
        Check `is_active` before using database-dependent methods.

    Attributes:
        is_active: Whether the MSF database is connected

    Example:
        >>> intel = Intel()
        >>> if intel.is_active:
        ...     hosts = intel.hosts()
        ...     creds = intel.creds()
        ... else:
        ...     print("Database not connected")
    """

    def __init__(self):
        """Initialize the Intel layer."""
        logger.debug("Intel layer initialized")

    @property
    def is_active(self) -> bool:
        """Check if the MSF database is connected.

        Returns:
            True if database operations will work
        """
        import msf
        try:
            return msf.db_active()
        except Exception as e:
            logger.warning(f"Database check failed: {e}")
            return False

    @property
    def driver(self) -> Optional[str]:
        """Get the database driver name.

        Returns:
            Driver name (e.g., "postgresql") or None if not connected
        """
        import msf
        try:
            return msf.db_driver()
        except Exception:
            return None

    # =========================================================================
    # Host Management
    # =========================================================================

    def hosts(self, workspace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all discovered hosts.

        Args:
            workspace: Optional workspace name (uses current if not specified)

        Returns:
            List of host dictionaries with address, os_name, etc.

        Example:
            >>> for host in intel.hosts():
            ...     print(f"{host['address']}: {host.get('os_name', 'unknown')}")
        """
        import msf
        if not self.is_active:
            logger.warning("Database not active, returning empty host list")
            return []

        try:
            hosts = msf.db_hosts()
            logger.debug(f"Retrieved {len(hosts)} hosts")
            return hosts
        except Exception as e:
            logger.error(f"Failed to get hosts: {e}")
            return []

    def get_host(self, address: str) -> Optional[Dict[str, Any]]:
        """Get a specific host by IP address.

        Args:
            address: IP address to look up

        Returns:
            Host dictionary or None if not found
        """
        import msf
        if not self.is_active:
            return None

        try:
            return msf.db_get_host(address)
        except Exception as e:
            logger.error(f"Failed to get host {address}: {e}")
            return None

    def report_host(
        self,
        address: str,
        os_name: Optional[str] = None,
        os_flavor: Optional[str] = None,
        name: Optional[str] = None,
        info: Optional[str] = None,
    ) -> Optional[int]:
        """Report/update a host in the database.

        Args:
            address: IP address
            os_name: Operating system name
            os_flavor: OS flavor/version
            name: Hostname
            info: Additional info

        Returns:
            Host ID if successful, None otherwise
        """
        import msf
        if not self.is_active:
            logger.warning("Database not active, cannot report host")
            return None

        opts: Dict[str, Any] = {"host": address}
        if os_name:
            opts["os_name"] = os_name
        if os_flavor:
            opts["os_flavor"] = os_flavor
        if name:
            opts["name"] = name
        if info:
            opts["info"] = info

        try:
            result = msf.db_report_host(opts)
            logger.info(f"Reported host {address}: id={result}")
            return result
        except Exception as e:
            logger.error(f"Failed to report host {address}: {e}")
            return None

    # =========================================================================
    # Service Management
    # =========================================================================

    def services(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        proto: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get discovered services.

        Args:
            host: Filter by host address
            port: Filter by port number
            proto: Filter by protocol ("tcp", "udp")

        Returns:
            List of service dictionaries

        Example:
            >>> for svc in intel.services(host="192.168.1.100"):
            ...     print(f":{svc['port']}/{svc['proto']} - {svc.get('name', 'unknown')}")
        """
        import msf
        if not self.is_active:
            return []

        try:
            services = msf.db_services()

            # Apply filters
            if host:
                services = [s for s in services if s.get("host") == host]
            if port:
                services = [s for s in services if s.get("port") == port]
            if proto:
                services = [s for s in services if s.get("proto") == proto]

            logger.debug(f"Retrieved {len(services)} services")
            return services
        except Exception as e:
            logger.error(f"Failed to get services: {e}")
            return []

    def report_service(
        self,
        host: str,
        port: int,
        proto: str = "tcp",
        name: Optional[str] = None,
        info: Optional[str] = None,
        state: str = "open",
    ) -> Optional[int]:
        """Report/update a service in the database.

        Args:
            host: IP address
            port: Port number
            proto: Protocol ("tcp" or "udp")
            name: Service name (e.g., "ssh", "http")
            info: Banner or additional info
            state: Service state ("open", "closed", "filtered")

        Returns:
            Service ID if successful, None otherwise
        """
        import msf
        if not self.is_active:
            logger.warning("Database not active, cannot report service")
            return None

        opts: Dict[str, Any] = {
            "host": host,
            "port": port,
            "proto": proto,
            "state": state,
        }
        if name:
            opts["name"] = name
        if info:
            opts["info"] = info

        try:
            result = msf.db_report_service(opts)
            logger.info(f"Reported service {host}:{port}/{proto}: id={result}")
            return result
        except Exception as e:
            logger.error(f"Failed to report service: {e}")
            return None

    # =========================================================================
    # Credential Management
    # =========================================================================

    def creds(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        service: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get stored credentials.

        Args:
            host: Filter by host address
            user: Filter by username
            service: Filter by service name

        Returns:
            List of credential dictionaries

        Example:
            >>> for cred in intel.creds(service="ssh"):
            ...     print(f"{cred['user']}:{cred['pass']} @ {cred.get('host')}")
        """
        import msf
        if not self.is_active:
            return []

        try:
            creds = msf.db_creds()

            # Apply filters
            if host:
                creds = [c for c in creds if c.get("host") == host]
            if user:
                creds = [c for c in creds if c.get("user") == user]
            if service:
                creds = [c for c in creds if c.get("sname") == service]

            logger.debug(f"Retrieved {len(creds)} credentials")
            return creds
        except Exception as e:
            logger.error(f"Failed to get credentials: {e}")
            return []

    def store_cred(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        service: Optional[str] = None,
        proto: str = "tcp",
        realm: Optional[str] = None,
        cred_type: str = "password",
    ) -> bool:
        """Store a credential in the database.

        Args:
            host: Target host address
            port: Service port
            user: Username
            password: Password or hash
            service: Service name (e.g., "ssh", "smb")
            proto: Protocol ("tcp" or "udp")
            realm: Domain/realm (for Windows)
            cred_type: Type ("password", "hash", "ntlm_hash")

        Returns:
            True if stored successfully

        Example:
            >>> intel.store_cred("192.168.1.100", 22, "admin", "password123", service="ssh")
            True
        """
        import msf
        if not self.is_active:
            logger.warning("Database not active, cannot store credential")
            return False

        opts: Dict[str, Any] = {
            "host": host,
            "port": port,
            "user": user,
            "pass": password,
            "proto": proto,
            "type": cred_type,
        }
        if service:
            opts["sname"] = service
        if realm:
            opts["realm"] = realm

        try:
            msf.db_report_cred(opts)
            logger.success(f"Stored credential: {user}@{host}:{port}")
            return True
        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            return False

    def find_creds_for_service(self, service: str) -> List[Dict[str, Any]]:
        """Find all credentials for a specific service type.

        Useful for credential reuse attacks.

        Args:
            service: Service name (e.g., "smb", "ssh", "winrm")

        Returns:
            List of matching credentials
        """
        return self.creds(service=service)

    # =========================================================================
    # Vulnerability Management
    # =========================================================================

    def vulns(
        self,
        host: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get discovered vulnerabilities.

        Args:
            host: Filter by host address
            name: Filter by vulnerability name

        Returns:
            List of vulnerability dictionaries
        """
        import msf
        if not self.is_active:
            return []

        try:
            vulns = msf.db_vulns()

            # Apply filters
            if host:
                vulns = [v for v in vulns if v.get("host") == host]
            if name:
                vulns = [v for v in vulns if name.lower() in v.get("name", "").lower()]

            logger.debug(f"Retrieved {len(vulns)} vulnerabilities")
            return vulns
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def report_vuln(
        self,
        host: str,
        name: str,
        info: Optional[str] = None,
        refs: Optional[List[str]] = None,
        port: Optional[int] = None,
        proto: Optional[str] = None,
    ) -> Optional[int]:
        """Report a vulnerability in the database.

        Args:
            host: Target host address
            name: Vulnerability name (e.g., "CVE-2017-7494")
            info: Description or additional info
            refs: Reference URLs or CVE IDs
            port: Affected port (optional)
            proto: Protocol (optional)

        Returns:
            Vulnerability ID if successful, None otherwise
        """
        import msf
        if not self.is_active:
            logger.warning("Database not active, cannot report vulnerability")
            return None

        opts: Dict[str, Any] = {"host": host, "name": name}
        if info:
            opts["info"] = info
        if refs:
            opts["refs"] = refs
        if port:
            opts["port"] = port
        if proto:
            opts["proto"] = proto

        try:
            result = msf.db_report_vuln(opts)
            logger.info(f"Reported vulnerability {name} on {host}: id={result}")
            return result
        except Exception as e:
            logger.error(f"Failed to report vulnerability: {e}")
            return None

    # =========================================================================
    # Loot Management
    # =========================================================================

    def loot(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get stored loot items.

        Args:
            host: Filter by host address

        Returns:
            List of loot dictionaries
        """
        import msf
        if not self.is_active:
            return []

        try:
            loot = msf.db_loot()

            if host:
                loot = [item for item in loot if item.get("host") == host]

            logger.debug(f"Retrieved {len(loot)} loot items")
            return loot
        except Exception as e:
            logger.error(f"Failed to get loot: {e}")
            return []

    # =========================================================================
    # Notes Management
    # =========================================================================

    def notes(self, host: Optional[str] = None, ntype: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get stored notes.

        Args:
            host: Filter by host address
            ntype: Filter by note type

        Returns:
            List of note dictionaries
        """
        import msf
        if not self.is_active:
            return []

        try:
            notes = msf.db_notes()

            if host:
                notes = [n for n in notes if n.get("host") == host]
            if ntype:
                notes = [n for n in notes if n.get("ntype") == ntype]

            return notes
        except Exception as e:
            logger.error(f"Failed to get notes: {e}")
            return []

    def add_note(
        self,
        host: str,
        ntype: str,
        data: str,
    ) -> bool:
        """Add a note to the database.

        Args:
            host: Target host address
            ntype: Note type identifier
            data: Note content

        Returns:
            True if added successfully
        """
        import msf
        if not self.is_active:
            return False

        try:
            msf.db_report_note({"host": host, "ntype": ntype, "data": data})
            logger.debug(f"Added note type {ntype} for {host}")
            return True
        except Exception as e:
            logger.error(f"Failed to add note: {e}")
            return False

    # =========================================================================
    # Workspace Management
    # =========================================================================

    @property
    def workspace(self) -> Optional[str]:
        """Get current workspace name."""
        import msf
        if not self.is_active:
            return None

        try:
            return msf.db_workspace()
        except Exception:
            return None

    def workspaces(self) -> List[str]:
        """List all workspaces.

        Returns:
            List of workspace names
        """
        import msf
        if not self.is_active:
            return []

        try:
            return msf.db_workspaces()
        except Exception as e:
            logger.error(f"Failed to list workspaces: {e}")
            return []

    def set_workspace(self, name: str) -> bool:
        """Switch to a different workspace.

        Args:
            name: Workspace name to switch to

        Returns:
            True if switch was successful
        """
        import msf
        if not self.is_active:
            return False

        try:
            msf.db_set_workspace(name)
            logger.info(f"Switched to workspace: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to set workspace: {e}")
            return False

    def create_workspace(self, name: str) -> bool:
        """Create a new workspace.

        Args:
            name: Workspace name to create

        Returns:
            True if created successfully
        """
        import msf
        if not self.is_active:
            return False

        try:
            msf.db_add_workspace(name)
            logger.info(f"Created workspace: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create workspace: {e}")
            return False

    # =========================================================================
    # Summary and Statistics
    # =========================================================================

    def summary(self) -> Dict[str, int]:
        """Get a summary of intelligence gathered.

        Returns:
            Dictionary with counts of hosts, services, creds, vulns
        """
        return {
            "hosts": len(self.hosts()),
            "services": len(self.services()),
            "credentials": len(self.creds()),
            "vulnerabilities": len(self.vulns()),
            "loot": len(self.loot()),
        }

    def __repr__(self) -> str:
        status = "active" if self.is_active else "inactive"
        return f"<Intel db={status}>"
