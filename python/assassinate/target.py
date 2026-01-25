"""Target module - represents a target to be assassinated.

The Target class tracks discovered information about a host, including
open ports, services, and vulnerabilities. This information accumulates
as profiling operations are performed.

Example:
    >>> target = Target("192.168.1.100")
    >>> target.add_port(445, "smb")
    >>> target.add_port(139, "netbios-ssn")
    >>> print(target)
    <Target 192.168.1.100 [139, 445] profiled=False>

    >>> target.has_service("smb")
    True
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set


class Target:
    """A target to be assassinated.

    Represents a host to be compromised. Tracks discovered information
    including open ports, services, and vulnerabilities. This data is
    populated during profiling operations and helps inform exploit selection.

    Attributes:
        host: IP address or hostname of the target
        ports: Set of discovered open ports
        services: Mapping of port numbers to service names
        vulns: List of discovered vulnerabilities (CVE IDs, etc.)

    Example:
        >>> target = Target("192.168.1.100")
        >>> target.add_port(445, "smb")
        >>> if target.has_service("smb"):
        ...     print("SMB is open, try SambaCry!")
    """

    __slots__ = ("host", "ports", "services", "vulns", "_profiled", "_notes")

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
    ):
        """Initialize a target.

        Args:
            host: IP address or hostname
            ports: Known open ports (optional)
            services: Port to service name mapping (optional)
        """
        self.host = host
        self.ports: Set[int] = set(ports or [])
        self.services: Dict[int, str] = services or {}
        self.vulns: List[str] = []
        self._profiled = False
        self._notes: List[str] = []

        # If services were provided, extract ports from them
        if services:
            self.ports.update(services.keys())

    def add_port(self, port: int, service: Optional[str] = None) -> None:
        """Record an open port on the target.

        Args:
            port: Port number
            service: Service name (optional, e.g., "smb", "http")
        """
        self.ports.add(port)
        if service:
            self.services[port] = service

    def has_port(self, port: int) -> bool:
        """Check if a port is known to be open.

        Args:
            port: Port number to check

        Returns:
            True if port is in the known open ports
        """
        return port in self.ports

    def has_service(self, service: str) -> bool:
        """Check if a service is running on the target.

        Args:
            service: Service name to check (case-insensitive)

        Returns:
            True if the service is in the services mapping
        """
        service_lower = service.lower()
        return any(s.lower() == service_lower for s in self.services.values())

    def get_port_for_service(self, service: str) -> Optional[int]:
        """Get the port number for a service.

        Args:
            service: Service name (case-insensitive)

        Returns:
            Port number or None if service not found
        """
        service_lower = service.lower()
        for port, svc in self.services.items():
            if svc.lower() == service_lower:
                return port
        return None

    def add_vuln(self, vuln: str) -> None:
        """Record a discovered vulnerability.

        Args:
            vuln: Vulnerability identifier (e.g., "CVE-2017-7494")
        """
        if vuln not in self.vulns:
            self.vulns.append(vuln)

    def add_note(self, note: str) -> None:
        """Add a note about the target.

        Args:
            note: Free-form note text
        """
        self._notes.append(note)

    @property
    def notes(self) -> List[str]:
        """Get all notes about the target."""
        return self._notes.copy()

    @property
    def profiled(self) -> bool:
        """Whether the target has been profiled."""
        return self._profiled

    def mark_profiled(self) -> None:
        """Mark the target as having been profiled."""
        self._profiled = True

    def summary(self) -> str:
        """Get a summary of what's known about the target.

        Returns:
            Multi-line string with target details
        """
        lines = [f"Target: {self.host}"]
        lines.append(f"  Profiled: {self._profiled}")

        if self.ports:
            sorted_ports = sorted(self.ports)
            port_strs = []
            for p in sorted_ports:
                if p in self.services:
                    port_strs.append(f"{p}/{self.services[p]}")
                else:
                    port_strs.append(str(p))
            lines.append(f"  Ports: {', '.join(port_strs)}")
        else:
            lines.append("  Ports: (none discovered)")

        if self.vulns:
            lines.append(f"  Vulns: {', '.join(self.vulns)}")

        if self._notes:
            lines.append("  Notes:")
            for note in self._notes:
                lines.append(f"    - {note}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        """Short representation of the target."""
        ports_str = ""
        if self.ports:
            sorted_ports = sorted(self.ports)
            ports_str = f" [{', '.join(str(p) for p in sorted_ports)}]"
        return f"<Target {self.host}{ports_str} profiled={self._profiled}>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        return self.host

    def __eq__(self, other: object) -> bool:
        """Targets are equal if they have the same host."""
        if isinstance(other, Target):
            return self.host == other.host
        if isinstance(other, str):
            return self.host == other
        return False

    def __hash__(self) -> int:
        """Hash based on host for use in sets/dicts."""
        return hash(self.host)
