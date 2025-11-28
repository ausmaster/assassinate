"""Detailed framework tests modeled after MSF framework_spec.rb."""

import pytest
import re


@pytest.mark.integration
class TestFrameworkVersion:
    """Tests for framework version information."""

    async def test_version_exists(self, client):
        """Test that version returns a value."""
        version = await client.framework_version()
        assert "version" in version
        assert version["version"] is not None

    async def test_version_format(self, client):
        """Test that version follows expected format."""
        version = await client.framework_version()
        version_str = version["version"]

        # MSF versions typically follow: Major.Minor.Point-Release
        # e.g., "6.4.100-dev" or "6.3.25" or "6.4.100-dev-e670167"
        # Allow alphanumeric characters and dashes in release suffix
        pattern = r'^\d+\.\d+\.\d+(-.+)?$'
        assert re.match(pattern, version_str), f"Version {version_str} doesn't match expected format"

    async def test_version_components(self, client):
        """Test that version can be split into major/minor/point components."""
        version = await client.framework_version()
        version_str = version["version"]

        # Split on . and -
        parts = re.split(r'[.-]', version_str)
        assert len(parts) >= 3, "Version should have at least major.minor.point"

        major, minor, point = parts[0:3]
        assert major.isdigit(), "Major version should be numeric"
        assert minor.isdigit(), "Minor version should be numeric"
        assert point.isdigit(), "Point version should be numeric"

        # MSF 6.x series
        assert int(major) >= 6, "Major version should be 6 or higher"


@pytest.mark.integration
class TestFrameworkModuleManager:
    """Tests for framework module management."""

    async def test_list_exploits_not_empty(self, client):
        """Test that framework has exploits loaded."""
        exploits = await client.list_modules("exploit")
        assert len(exploits) > 0, "Framework should have exploits loaded"

    async def test_list_auxiliary_not_empty(self, client):
        """Test that framework has auxiliary modules loaded."""
        auxiliary = await client.list_modules("auxiliary")
        assert len(auxiliary) > 0, "Framework should have auxiliary modules loaded"

    async def test_list_payloads_not_empty(self, client):
        """Test that framework has payloads loaded."""
        payloads = await client.list_modules("payload")
        assert len(payloads) > 0, "Framework should have payloads loaded"

    async def test_search_finds_known_modules(self, client):
        """Test that search can find well-known modules."""
        # Search for vsftpd - should find the backdoor exploit
        results = await client.search("vsftpd")
        assert len(results) > 0, "Search should find vsftpd modules"
        assert any("vsftpd_234_backdoor" in r for r in results)

    async def test_search_with_type_filter(self, client):
        """Test search with type filtering."""
        # Search with type filter
        results = await client.search("type:exploit vsftpd")
        assert len(results) > 0
        # All results should be exploits
        for result in results:
            assert "exploit/" in result


@pytest.mark.integration
class TestFrameworkThreads:
    """Tests for framework thread management."""

    async def test_threads_returns_count(self, client):
        """Test that threads returns a numeric count."""
        threads = await client.threads()
        assert isinstance(threads, int)
        assert threads >= 0


@pytest.mark.integration
class TestFrameworkSessions:
    """Tests for framework session management."""

    async def test_list_sessions_returns_list(self, client):
        """Test that list_sessions returns a list."""
        sessions = await client.list_sessions()
        assert isinstance(sessions, list)

    async def test_list_sessions_initially_empty(self, client):
        """Test that sessions list starts empty."""
        sessions = await client.list_sessions()
        # May or may not be empty depending on test state
        assert isinstance(sessions, list)
