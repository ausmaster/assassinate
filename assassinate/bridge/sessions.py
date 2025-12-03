"""MSF Session management via IPC.

Provides access to active sessions from successful exploits.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from assassinate.bridge.client_utils import call_client_method

if TYPE_CHECKING:
    from assassinate.ipc.protocol import ClientProtocol


def _run_async(coro):
    """Helper to run async code synchronously."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


class SessionManager:
    """Manages active MSF sessions via IPC.

    Provides access to established sessions from successful exploits.
    """

    _client: ClientProtocol

    def __init__(self, client: ClientProtocol) -> None:
        """Initialize SessionManager with IPC client.

        Args:
            client: Connected client instance (MsfClient or SyncMsfClient).

        Note:
            This is called internally via Framework.sessions().
        """
        self._client = client

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
        return _run_async(call_client_method(self._client, "list_sessions"))

    def get(self, session_id: int) -> Session | None:
        """Get session by ID.

        Args:
            session_id: Session ID to retrieve.

        Returns:
            Session instance or None if not found.

        Example:
            >>> sm = fw.sessions()
            >>> session = sm.get(1)
            >>> if session:
            ...     print(f"Session {session_id} found")
        """
        # Check if session exists in list
        sessions = self.list()
        if session_id in sessions:
            return Session(session_id, self._client)
        return None

    def kill(self, session_id: int) -> bool:
        """Kill a session by ID.

        Args:
            session_id: Session ID to terminate.

        Returns:
            True if session was killed, False if not found.

        Note:
            This method requires daemon support - not yet implemented.

        Example:
            >>> sm = fw.sessions()
            >>> if sm.kill(1):
            ...     print("Session 1 terminated")
        """
        # TODO: Add kill_session IPC method to daemon
        raise NotImplementedError(
            "Session.kill() requires daemon support (not yet implemented)"
        )

    def __repr__(self) -> str:
        """Return string representation of SessionManager.

        Returns:
            String representation.
        """
        # Don't call self.list() here as it's async and __repr__ should be sync
        return "<SessionManager>"


class Session:
    """Active MSF session via IPC.

    Represents a connection to a compromised target. Can be a shell,
    meterpreter, or other session type.

    Note:
        Most session interaction methods require daemon support and are
        not yet implemented in the IPC layer.
    """

    _session_id: int
    _client: ClientProtocol

    def __init__(self, session_id: int, client: ClientProtocol) -> None:
        """Initialize Session wrapper.

        Args:
            session_id: Session ID number.
            client: Connected client instance (MsfClient or SyncMsfClient).

        Note:
            This is called internally via SessionManager.get().
        """
        self._session_id = session_id
        self._client = client

    @property
    def id(self) -> int:
        """Get session ID.

        Returns:
            Session ID number.
        """
        return self._session_id

    def alive(self) -> bool:
        """Check if session is alive.

        Returns:
            True if session is active.

        Note:
            This method requires daemon support - not yet implemented.
            Currently returns True if session ID exists.
        """
        # TODO: Add session_alive IPC method to daemon
        # For now, just check if session is still in the list
        try:
            manager = SessionManager(self._client)
            return self._session_id in manager.list()
        except Exception:
            return False

    def kill(self) -> None:
        """Kill this session.

        Note:
            This method requires daemon support - not yet implemented.

        Raises:
            NotImplementedError: Method not yet supported via IPC.
        """
        raise NotImplementedError(
            "Session.kill() requires daemon support (not yet implemented)"
        )

    def execute(self, command: str) -> str:
        """Execute a command in the session.

        Args:
            command: Command to execute.

        Returns:
            Command output.

        Note:
            This method requires daemon support - not yet implemented.

        Raises:
            NotImplementedError: Method not yet supported via IPC.
        """
        raise NotImplementedError(
            "Session.execute() requires daemon support (not yet implemented)"
        )

    def write(self, data: str) -> int:
        """Write data to the session.

        Args:
            data: Data to write.

        Returns:
            Number of bytes written.

        Note:
            This method requires daemon support - not yet implemented.

        Raises:
            NotImplementedError: Method not yet supported via IPC.
        """
        raise NotImplementedError(
            "Session.write() requires daemon support (not yet implemented)"
        )

    def read(self, length: int | None = None) -> str:
        """Read data from the session.

        Args:
            length: Number of bytes to read (None = all available).

        Returns:
            Data read from session.

        Note:
            This method requires daemon support - not yet implemented.

        Raises:
            NotImplementedError: Method not yet supported via IPC.
        """
        raise NotImplementedError(
            "Session.read() requires daemon support (not yet implemented)"
        )

    def __repr__(self) -> str:
        """Return string representation of Session.

        Returns:
            String representation.
        """
        return f"<Session id={self._session_id}>"
