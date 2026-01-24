"""Pythonic wrapper for PySession with property-based access."""

from typing import Optional


class Session:
    """
    Rich Python wrapper around MSF sessions.

    Provides intuitive property-based access to session metadata
    and methods for interacting with the compromised host.

    Example:
        session = msf.get_session(1)
        print(session.host)          # "192.168.1.100"
        print(session.session_type)  # "shell"
        print(session.alive)         # True

        # Execute commands
        output = session.run_cmd("whoami")
        print(output)  # "root"

        # Kill when done
        session.kill()
    """

    def __init__(self, rust_session):
        """Initialize wrapper around a PySession from Rust."""
        self._rust = rust_session

    # === Properties (Pythonic attribute access) ===

    @property
    def sid(self) -> int:
        """Session ID."""
        return self._rust.sid()

    @property
    def session_type(self) -> str:
        """Session type (shell, meterpreter, etc.)."""
        return self._rust.session_type()

    @property
    def info(self) -> str:
        """Session info string."""
        return self._rust.info()

    @property
    def alive(self) -> bool:
        """True if session is still active."""
        return self._rust.alive()

    @property
    def desc(self) -> str:
        """Session description."""
        return self._rust.desc()

    @property
    def host(self) -> str:
        """Target host IP address."""
        return self._rust.session_host()

    @property
    def port(self) -> int:
        """Target port."""
        return self._rust.session_port()

    @property
    def tunnel_peer(self) -> str:
        """Tunnel peer address."""
        return self._rust.tunnel_peer()

    @property
    def target_host(self) -> str:
        """Target host."""
        return self._rust.target_host()

    @property
    def via_exploit(self) -> str:
        """Exploit that created this session."""
        return self._rust.via_exploit()

    @property
    def via_payload(self) -> str:
        """Payload used for this session."""
        return self._rust.via_payload()

    # === Shell Methods ===

    def run_cmd(self, cmd: str, timeout: Optional[int] = None) -> str:
        """
        Execute a command and return the output.

        Args:
            cmd: Command to execute
            timeout: Optional timeout in seconds

        Returns:
            Command output as string
        """
        return self._rust.run_cmd(cmd, timeout)

    def read(self, length: Optional[int] = None) -> str:
        """Read available data from session."""
        return self._rust.read(length)

    def write(self, data: str) -> int:
        """
        Write data to session.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        return self._rust.write(data)

    def kill(self) -> None:
        """Kill this session."""
        self._rust.kill()

    def __repr__(self) -> str:
        try:
            return f"<Session {self.sid}: {self.session_type} @ {self.host}:{self.port}>"
        except Exception:
            return f"<Session {self._rust.sid()}>"

    def __bool__(self) -> bool:
        """Session is truthy if alive."""
        try:
            return self.alive
        except Exception:
            return False
