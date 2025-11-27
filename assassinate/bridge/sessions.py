"""MSF Session management.

Provides access to active sessions from successful exploits.
"""

from __future__ import annotations

from typing import Any


class SessionManager:
    """Manages active MSF sessions.

    Provides access to established sessions from successful exploits.
    """

    _instance: Any  # The underlying PyO3 SessionManager instance

    def __init__(self, instance: Any) -> None:
        """Initialize SessionManager wrapper.

        Args:
            instance: PyO3 SessionManager instance.

        Note:
            This is called internally via Framework.sessions().
        """
        self._instance = instance

    def list(self) -> list[int]:
        """List all active session IDs.

        Returns:
            List of session IDs (e.g., [1, 2, 5]).

        Example:
            >>> sm = fw.sessions()
            >>> session_ids = sm.list()
            >>> print(f"Active sessions: {session_ids}")
            Active sessions: [1, 2]
        """
        return list(self._instance.list())

    def get(self, session_id: int) -> Session | None:
        """Get session by ID.

        Args:
            session_id: Session ID to retrieve.

        Returns:
            Session instance or None if not found.

        Example:
            >>> sm = fw.sessions()
            >>> session = sm.get(1)
            >>> if session and session.alive():
            ...     output = session.execute("whoami")
        """
        instance = self._instance.get(session_id)
        return Session(instance) if instance is not None else None

    def __repr__(self) -> str:
        """Return string representation of SessionManager.

        Returns:
            String representation.
        """
        session_count = len(self.list())
        return f"<SessionManager sessions={session_count}>"


class Session:
    """Active MSF session.

    Represents a connection to a compromised target. Can be a shell,
    meterpreter, or other session type.
    """

    _instance: Any  # The underlying PyO3 Session instance

    def __init__(self, instance: Any) -> None:
        """Initialize Session wrapper.

        Args:
            instance: PyO3 Session instance.

        Note:
            This is called internally via SessionManager.get().
        """
        self._instance = instance

    def info(self) -> str:
        """Get session information.

        Returns:
            Session information string.

        Example:
            >>> session = sm.get(1)
            >>> info = session.info()
            >>> print(info)
        """
        return str(self._instance.info())

    def alive(self) -> bool:
        """Check if session is still alive.

        Returns:
            True if session is active, False if closed/dead.

        Example:
            >>> session = sm.get(1)
            >>> if session.alive():
            ...     print("Session is active")
        """
        return bool(self._instance.alive())

    def execute(self, command: str) -> str:
        """Execute a command and return output.

        Args:
            command: Command to execute.

        Returns:
            Command output.

        Raises:
            RuntimeError: If session is dead or command fails.

        Example:
            >>> session = sm.get(1)
            >>> output = session.execute("whoami")
            >>> print(output)
            root
        """
        return str(self._instance.execute(command))

    def session_type(self) -> str:
        """Get the session type.

        Returns:
            Session type (e.g., "shell", "meterpreter", "powershell").

        Example:
            >>> session = sm.get(1)
            >>> print(session.session_type())
            shell
        """
        return str(self._instance.session_type())

    def kill(self) -> None:
        """Kill/close the session.

        Example:
            >>> session = sm.get(1)
            >>> session.kill()
            >>> print(session.alive())
            False
        """
        self._instance.kill()

    def write(self, data: str) -> int:
        r"""Write data to the session.

        Args:
            data: Data to write to session.

        Returns:
            Number of bytes written.

        Raises:
            RuntimeError: If write fails or session is dead.

        Example:
            >>> session = sm.get(1)
            >>> bytes_written = session.write("whoami\n")
            >>> print(f"Wrote {bytes_written} bytes")
        """
        return int(self._instance.write(data))

    def read(self, length: int | None = None) -> str:
        r"""Read data from the session.

        Args:
            length: Optional maximum bytes to read. If None, reads all
                available data.

        Returns:
            Data read from session.

        Raises:
            RuntimeError: If read fails or session is dead.

        Example:
            >>> session = sm.get(1)
            >>> session.write("whoami\n")
            >>> output = session.read()
            >>> print(output)
            root
        """
        return str(self._instance.read(length))

    def run_cmd(self, command: str) -> str:
        """Run a command and return output (meterpreter sessions).

        Args:
            command: Meterpreter command to run.

        Returns:
            Command output.

        Raises:
            RuntimeError: If session is not meterpreter or command fails.

        Example:
            >>> session = sm.get(1)  # Meterpreter session
            >>> info = session.run_cmd("sysinfo")
            >>> print(info)
        """
        return str(self._instance.run_cmd(command))

    def desc(self) -> str:
        """Get session description.

        Returns:
            Human-readable session description.

        Example:
            >>> session = sm.get(1)
            >>> print(session.desc())
            Command shell on 192.168.1.100:4444
        """
        return str(self._instance.desc())

    def tunnel_peer(self) -> str:
        """Get tunnel peer information.

        Returns:
            Tunnel peer address (e.g., "192.168.1.100:4444").

        Example:
            >>> session = sm.get(1)
            >>> print(session.tunnel_peer())
            192.168.1.100:4444
        """
        return str(self._instance.tunnel_peer())

    def target_host(self) -> str:
        """Get target host IP address.

        Returns:
            Target IP address.

        Example:
            >>> session = sm.get(1)
            >>> print(session.target_host())
            192.168.1.100
        """
        return str(self._instance.target_host())

    def __repr__(self) -> str:
        """Return string representation of Session.

        Returns:
            String representation.
        """
        session_type = self.session_type()
        alive = "alive" if self.alive() else "dead"
        return f"<Session type={session_type} status={alive}>"
