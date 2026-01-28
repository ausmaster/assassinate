"""Tests for framework-level operations.

Tests framework version, module listing, and search functionality.
"""

import re

import pytest

import assassinate


class TestFrameworkVersion:
    """Tests for framework version information."""

    def test_version_exists(self, msf_init):
        """Test that version returns a value."""
        version = assassinate.framework_version()
        assert version is not None
        assert isinstance(version, str)
        assert len(version) > 0

    def test_version_format(self, msf_init):
        """Test that version follows expected format."""
        version = assassinate.framework_version()

        # MSF versions typically follow: Major.Minor.Point-Release
        # e.g., "6.4.100-dev" or "6.3.25" or "6.4.100-dev-e670167"
        pattern = r"^\d+\.\d+\.\d+(-.+)?$"
        assert re.match(pattern, version), (
            f"Version {version} doesn't match expected format"
        )

    def test_version_components(self, msf_init):
        """Test that version can be split into major/minor/point components."""
        version = assassinate.framework_version()

        # Split on . and -
        parts = re.split(r"[.-]", version)
        assert len(parts) >= 3, "Version should have at least major.minor.point"

        major, minor, point = parts[0:3]
        assert major.isdigit(), "Major version should be numeric"
        assert minor.isdigit(), "Minor version should be numeric"
        assert point.isdigit(), "Point version should be numeric"

        # MSF 6.x series
        assert int(major) >= 6, "Major version should be 6 or higher"


class TestFrameworkModuleManager:
    """Tests for framework module management."""

    def test_list_exploits_not_empty(self, msf_init):
        """Test that framework has exploits loaded."""
        exploits = assassinate.list_modules("exploit")
        assert len(exploits) > 0, "Framework should have exploits loaded"

    def test_list_auxiliary_not_empty(self, msf_init):
        """Test that framework has auxiliary modules loaded."""
        auxiliary = assassinate.list_modules("auxiliary")
        assert len(auxiliary) > 0, "Framework should have auxiliary modules loaded"

    def test_list_payloads_not_empty(self, msf_init):
        """Test that framework has payloads loaded."""
        payloads = assassinate.list_modules("payload")
        assert len(payloads) > 0, "Framework should have payloads loaded"

    def test_list_post_not_empty(self, msf_init):
        """Test that framework has post modules loaded."""
        post = assassinate.list_modules("post")
        assert len(post) > 0, "Framework should have post modules loaded"

    def test_list_encoders_not_empty(self, msf_init):
        """Test that framework has encoders loaded."""
        encoders = assassinate.list_modules("encoder")
        assert len(encoders) > 0, "Framework should have encoders loaded"

    def test_list_nops_not_empty(self, msf_init):
        """Test that framework has NOP modules loaded."""
        nops = assassinate.list_modules("nop")
        assert len(nops) > 0, "Framework should have NOP modules loaded"

    def test_search_finds_known_modules(self, msf_init):
        """Test that search can find well-known modules."""
        # Search for samba - should find SambaCry and other samba modules
        results = assassinate.search("samba")
        assert len(results) > 0, "Search should find samba modules"
        assert any("is_known_pipename" in r for r in results)

    def test_search_with_type_filter(self, msf_init):
        """Test search with type filtering."""
        # Search with type filter
        results = assassinate.search("type:exploit samba")
        assert len(results) > 0
        # All results should be exploits
        for result in results:
            assert "exploit/" in result


class TestFrameworkSessions:
    """Tests for framework session management."""

    def test_list_sessions_returns_list(self, msf_init):
        """Test that list_sessions returns a list."""
        sessions = assassinate.list_sessions()
        assert isinstance(sessions, list)


class TestFrameworkJobs:
    """Tests for framework job management."""

    def test_job_list_returns_list(self, msf_init):
        """Test that job_list returns a list."""
        jobs = assassinate.job_list()
        assert isinstance(jobs, list)


class TestFrameworkStats:
    """Tests for framework module statistics."""

    def test_module_stats_returns_dict(self, msf_init):
        """Test that module_stats returns a dictionary."""
        stats = assassinate.module_stats()
        assert isinstance(stats, dict)

    def test_module_stats_has_expected_keys(self, msf_init):
        """Test that module_stats contains expected module types."""
        stats = assassinate.module_stats()
        expected_keys = ["exploits", "auxiliary", "post", "payloads", "encoders", "nops"]
        for key in expected_keys:
            assert key in stats, f"module_stats should contain '{key}'"

    def test_module_stats_values_are_positive(self, msf_init):
        """Test that module counts are positive integers."""
        stats = assassinate.module_stats()
        for key, value in stats.items():
            assert isinstance(value, int), f"{key} should be an integer"
            assert value >= 0, f"{key} should be non-negative"

    def test_module_stats_has_reasonable_counts(self, msf_init):
        """Test that stats show reasonable module counts."""
        stats = assassinate.module_stats()
        # MSF should have thousands of exploits
        assert stats.get("exploits", 0) > 1000, "Should have >1000 exploits"
        # MSF should have hundreds of auxiliary modules
        assert stats.get("auxiliary", 0) > 500, "Should have >500 auxiliary"
        # MSF should have payloads
        assert stats.get("payloads", 0) > 100, "Should have >100 payloads"


class TestFrameworkReload:
    """Tests for framework module reload functionality."""

    def test_reload_modules_returns_dict(self, msf_init):
        """Test that reload_modules returns a dictionary."""
        result = assassinate.reload_modules()
        assert isinstance(result, dict)

    def test_reload_modules_preserves_counts(self, msf_init):
        """Test that reload doesn't lose modules."""
        stats_before = assassinate.module_stats()
        assassinate.reload_modules()
        stats_after = assassinate.module_stats()
        # Counts should be similar (might change slightly if dev modules change)
        for key in stats_before:
            if key in stats_after:
                # Allow some variance but not dramatic loss
                assert stats_after[key] >= stats_before[key] * 0.9, (
                    f"{key} count dropped significantly after reload"
                )
