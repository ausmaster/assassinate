"""Test create_shell_session function.

Requires INTEGRATION_TESTS=true and test-shell container running.
"""

import os
import pytest
import assassinate


@pytest.fixture(scope="module")
def framework():
    """Initialize MSF framework once for the test module."""
    msf_root = os.environ.get("MSF_ROOT", os.path.expanduser("~/Projects/metasploit-framework"))
    if not assassinate.is_initialized():
        assassinate.init_msf(msf_root)
    yield


@pytest.mark.skipif(
    os.environ.get("INTEGRATION_TESTS", "").lower() != "true",
    reason="Integration tests disabled (set INTEGRATION_TESTS=true)"
)
class TestCreateShellSession:
    """Test creating sessions from raw bind shells."""

    def test_creates_session_from_bind_shell(self, framework):
        """create_shell_session() connects to bind shell and creates session."""
        # The test-shell container runs socat bind shell on port 4444
        # Exposed to host as localhost:4444
        host = "127.0.0.1"
        port = 4444
        timeout = 10

        # Create session
        session_id = assassinate.create_shell_session(host, port, timeout)
        assert isinstance(session_id, int)
        assert session_id > 0

        try:
            # Get session object
            session = assassinate.get_session(session_id)
            assert session is not None

            # Run a command
            output = session.run_cmd("echo hello")
            assert "hello" in output

            # Check session type
            assert session.session_type == "shell"
        finally:
            # Cleanup
            assassinate.kill_session(session_id)

    def test_creates_multiple_sessions(self, framework):
        """Can create multiple sessions from same bind shell."""
        host = "127.0.0.1"
        port = 4444
        timeout = 10

        # Create first session
        session_id1 = assassinate.create_shell_session(host, port, timeout)

        try:
            # Verify first session works
            session1 = assassinate.get_session(session_id1)
            assert session1 is not None
            output1 = session1.run_cmd("id")
            assert "uid=" in output1
        finally:
            assassinate.kill_session(session_id1)
