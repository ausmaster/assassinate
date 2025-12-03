"""Unit tests for synchronous API.

Tests that the sync API wrapper works correctly and provides
synchronous access to MSF functionality.
"""

import pytest


@pytest.mark.integration
class TestSyncAPI:
    """Tests for synchronous API."""

    def test_sync_initialize_and_version(self, daemon_process):
        """Test sync initialize and get_version."""
        from assassinate.bridge import get_version, initialize

        # Initialize connection
        initialize()

        # Get version
        version = get_version()
        assert version is not None
        assert isinstance(version, str)
        assert len(version) > 0

    def test_sync_framework_version(self, daemon_process):
        """Test sync Framework class."""
        from assassinate.bridge import Framework

        fw = Framework()
        version = fw.version()

        assert version is not None
        assert isinstance(version, str)
        # MSF versions typically follow: Major.Minor.Point-Release
        assert "." in version

    def test_sync_framework_list_modules(self, daemon_process):
        """Test sync list_modules."""
        from assassinate.bridge import Framework

        fw = Framework()
        exploits = fw.list_modules("exploit")

        assert isinstance(exploits, list)
        assert len(exploits) > 0
        assert all(isinstance(e, str) for e in exploits)

    def test_sync_framework_search(self, daemon_process):
        """Test sync search."""
        from assassinate.bridge import Framework

        fw = Framework()
        results = fw.search("vsftpd")

        assert isinstance(results, list)
        assert len(results) > 0
        # Should find the vsftpd backdoor exploit
        assert any("vsftpd" in r.lower() for r in results)

    def test_sync_framework_threads(self, daemon_process):
        """Test sync threads."""
        from assassinate.bridge import Framework

        fw = Framework()
        threads = fw.threads()

        assert isinstance(threads, int)
        assert threads >= 0

    def test_sync_framework_threads_enabled(self, daemon_process):
        """Test sync threads_enabled."""
        from assassinate.bridge import Framework

        fw = Framework()
        enabled = fw.threads_enabled()

        assert isinstance(enabled, bool)

    def test_sync_can_be_called_from_sync_context(self, daemon_process):
        """Test that sync API works from pure sync code (no event loop)."""
        from assassinate.bridge import Framework, initialize

        # This should work without any async/await
        initialize()
        fw = Framework()
        version = fw.version()

        assert isinstance(version, str)

    def test_sync_multiple_calls(self, daemon_process):
        """Test multiple sync calls in sequence."""
        from assassinate.bridge import Framework

        fw = Framework()

        # Multiple calls should work fine
        v1 = fw.version()
        v2 = fw.version()
        v3 = fw.version()

        assert v1 == v2 == v3

    def test_sync_framework_repr(self, daemon_process):
        """Test Framework __repr__."""
        from assassinate.bridge import Framework

        fw = Framework()
        repr_str = repr(fw)

        assert isinstance(repr_str, str)
        assert "Framework" in repr_str


# Note: We don't test mixing sync and async APIs in the same test
# because it causes event loop conflicts. Each API should be tested
# separately, and they're tested against the same daemon in different tests.
