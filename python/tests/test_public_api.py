"""Tests for public API completeness and correctness.

Verifies that all expected exports are available and that basic API operations work.
"""

import pytest

import assassinate


class TestSearchAPI:
    """Tests for search functionality."""

    def test_search_finds_modules(self, msf_init):
        """Test that search finds matching modules."""
        results = assassinate.search("samba")
        assert len(results) > 0, "Should find samba modules"

    def test_search_cve(self, msf_init):
        """Test searching by CVE number."""
        results = assassinate.search("CVE-2017-7494")
        assert len(results) > 0, "Should find CVE modules"

    def test_search_empty_for_nonsense(self, msf_init):
        """Test that nonsense query returns empty list."""
        results = assassinate.search("xyznonexistent123")
        assert len(results) == 0, "Nonsense query should return empty"


class TestSessionAPI:
    """Tests for session management API."""

    def test_list_sessions_returns_list(self, msf_init):
        """Test that list_sessions returns a list."""
        sessions = assassinate.list_sessions()
        assert isinstance(sessions, list)

    def test_get_session_invalid_returns_none(self, msf_init):
        """Test that get_session with invalid ID returns None."""
        session = assassinate.get_session(99999)
        assert session is None

    def test_kill_session_invalid_returns_false(self, msf_init):
        """Test that kill_session with invalid ID returns False."""
        result = assassinate.kill_session(99999)
        assert result is False


class TestSessionClass:
    """Tests for Session wrapper class."""

    def test_session_class_has_expected_attributes(self, msf_init):
        """Test that Session class has all expected attributes."""
        expected_attrs = [
            "sid",
            "session_type",
            "alive",
            "host",
            "port",
            "via_exploit",
            "via_payload",
            "run_cmd",
            "read",
            "write",
            "kill",
        ]
        for attr in expected_attrs:
            assert hasattr(assassinate.Session, attr), f"Session should have {attr}"


class TestModuleAPI:
    """Tests for module API."""

    def test_create_module_returns_module(self, msf_init):
        """Test that create_module returns a module object."""
        module = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        assert isinstance(module, assassinate.ExploitModule)

    def test_module_options_settable(self, msf_init):
        """Test that module options can be set."""
        module = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        module.options.RHOSTS = "192.168.1.100"
        assert module.options.RHOSTS == "192.168.1.100"

    def test_exploit_method_signature(self, msf_init):
        """Test that exploit method has proper signature."""
        import inspect

        module = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        sig = inspect.signature(module.exploit)
        params = list(sig.parameters.keys())
        assert "payload" in params, "exploit() should have payload param"
        assert "timeout" in params, "exploit() should have timeout param"


class TestModuleExports:
    """Tests for module exports completeness."""

    def test_core_exports_available(self, msf_init):
        """Test that core exports are available."""
        core_exports = [
            "init_msf",
            "is_initialized",
            "framework_version",
        ]
        for export in core_exports:
            assert hasattr(msf, export), f"Module should export {export}"

    def test_module_exports_available(self, msf_init):
        """Test that module-related exports are available."""
        module_exports = [
            "create_module",
            "list_modules",
            "search",
            "get_module_info",
        ]
        for export in module_exports:
            assert hasattr(msf, export), f"Module should export {export}"

    def test_session_exports_available(self, msf_init):
        """Test that session-related exports are available."""
        session_exports = [
            "Session",
            "get_session",
            "list_sessions",
            "kill_session",
        ]
        for export in session_exports:
            assert hasattr(msf, export), f"Module should export {export}"

    def test_class_exports_available(self, msf_init):
        """Test that class exports are available."""
        class_exports = [
            "BaseModule",
            "ExploitModule",
            "AuxiliaryModule",
            "PostModule",
            "EvasionModule",
            "PayloadModule",
            "EncoderModule",
            "NopModule",
            "ModuleOptions",
            "AssassinateError",
        ]
        for export in class_exports:
            assert hasattr(msf, export), f"Module should export {export}"

    def test_job_exports_available(self, msf_init):
        """Test that job-related exports are available."""
        job_exports = [
            "job_list",
            "job_info",
            "job_kill",
        ]
        for export in job_exports:
            assert hasattr(msf, export), f"Module should export {export}"
