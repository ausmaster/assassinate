"""Tests for SessionManager functionality.

Note: These tests verify the IPC layer works correctly. Full session interaction
tests would require running actual exploits to create sessions, which is beyond
the scope of unit testing.
"""

import pytest


@pytest.mark.integration
class TestSessionList:
    """Tests for listing sessions."""

    async def test_list_sessions_returns_list(self, client):
        """Test that listing sessions returns a list."""
        session_ids = await client.list_sessions()
        assert isinstance(session_ids, list)
        # May be empty if no active sessions
        assert session_ids is not None

    async def test_list_sessions_contains_integers(self, client):
        """Test that session IDs are integers."""
        session_ids = await client.list_sessions()
        for session_id in session_ids:
            assert isinstance(session_id, int)


@pytest.mark.integration
class TestSessionMetadata:
    """Tests for getting session metadata."""

    async def test_get_nonexistent_session(self, client):
        """Test getting metadata for nonexistent session."""
        # Use a very high ID that's unlikely to exist
        session_data = await client.session_get(99999)
        # Should return None or a dict with session=null
        assert session_data is None or session_data.get("session") is None

    async def test_session_type_nonexistent(self, client):
        """Test getting type for nonexistent session."""
        session_type = await client.session_type(99999)
        # Should return None for nonexistent session
        assert session_type is None

    async def test_session_alive_nonexistent(self, client):
        """Test checking if nonexistent session is alive."""
        alive = await client.session_alive(99999)
        # Should return False for nonexistent session
        assert alive is False

    async def test_session_info_nonexistent(self, client):
        """Test getting info for nonexistent session."""
        info = await client.session_info(99999)
        assert info is None


@pytest.mark.integration
class TestSessionKill:
    """Tests for killing sessions."""

    async def test_kill_nonexistent_session(self, client):
        """Test killing a nonexistent session."""
        result = await client.session_kill(99999)
        assert isinstance(result, bool)
        # Should return False for nonexistent session
        assert result is False


@pytest.mark.integration
class TestSessionProperties:
    """Tests for session property getters."""

    async def test_session_desc_nonexistent(self, client):
        """Test getting description for nonexistent session."""
        desc = await client.session_desc(99999)
        assert desc is None

    async def test_session_host_nonexistent(self, client):
        """Test getting host for nonexistent session."""
        host = await client.session_host(99999)
        assert host is None

    async def test_session_port_nonexistent(self, client):
        """Test getting port for nonexistent session."""
        port = await client.session_port(99999)
        assert port is None

    async def test_session_tunnel_peer_nonexistent(self, client):
        """Test getting tunnel peer for nonexistent session."""
        tunnel_peer = await client.session_tunnel_peer(99999)
        assert tunnel_peer is None

    async def test_session_via_exploit_nonexistent(self, client):
        """Test getting via_exploit for nonexistent session."""
        via_exploit = await client.session_via_exploit(99999)
        assert via_exploit is None

    async def test_session_via_payload_nonexistent(self, client):
        """Test getting via_payload for nonexistent session."""
        via_payload = await client.session_via_payload(99999)
        assert via_payload is None


@pytest.mark.integration
class TestSessionInteraction:
    """Tests for session interaction (read/write/execute).

    Note: These tests verify the IPC layer handles requests correctly,
    but will fail for nonexistent sessions (expected behavior).
    """

    async def test_read_fails_on_nonexistent(self, client):
        """Test that read raises error for nonexistent session."""
        with pytest.raises(Exception):  # Will raise RemoteError
            await client.session_read(99999)

    async def test_write_fails_on_nonexistent(self, client):
        """Test that write raises error for nonexistent session."""
        with pytest.raises(Exception):  # Will raise RemoteError
            await client.session_write(99999, "test\n")

    async def test_execute_fails_on_nonexistent(self, client):
        """Test that execute raises error for nonexistent session."""
        with pytest.raises(Exception):  # Will raise RemoteError
            await client.session_execute(99999, "whoami")

    async def test_run_cmd_fails_on_nonexistent(self, client):
        """Test that run_cmd raises error for nonexistent session."""
        with pytest.raises(Exception):  # Will raise RemoteError
            await client.session_run_cmd(99999, "sysinfo")


@pytest.mark.integration
class TestSessionWorkflow:
    """Tests for complete session workflows."""

    async def test_list_and_check_metadata(self, client):
        """Test listing sessions and checking metadata for each."""
        session_ids = await client.list_sessions()

        # For each active session, verify we can get metadata
        for session_id in session_ids:
            # These should not raise exceptions
            session_type = await client.session_type(session_id)
            assert session_type is None or isinstance(session_type, str)

            alive = await client.session_alive(session_id)
            assert isinstance(alive, bool)

            info = await client.session_info(session_id)
            assert info is None or isinstance(info, str)

    async def test_operations_dont_crash(self, client):
        """Test that session operations handle edge cases gracefully."""
        # These should not raise exceptions for getting metadata
        await client.list_sessions()
        await client.session_type(0)
        await client.session_alive(-1)
        await client.session_info(99999)
        await client.session_desc(99999)
        await client.session_host(99999)

        # Kill operations should return False for invalid IDs
        result = await client.session_kill(0)
        assert isinstance(result, bool)

        result = await client.session_kill(-1)
        assert isinstance(result, bool)
