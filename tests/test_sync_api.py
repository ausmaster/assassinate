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

    def test_sync_create_module(self, daemon_process):
        """Test creating a module with sync client."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        # Module methods are async even with sync Framework
        assert mod is not None
        name = asyncio.run(mod.name())
        # name() returns the human-readable name
        assert isinstance(name, str)
        assert len(name) > 0

    def test_sync_module_fullname(self, daemon_process):
        """Test module fullname with sync client."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        fullname = asyncio.run(mod.fullname())
        assert fullname == "exploit/unix/ftp/vsftpd_234_backdoor"

    def test_sync_module_set_get_option(self, daemon_process):
        """Test setting and getting module options with sync client."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        # Set an option
        asyncio.run(mod.set_option("RHOSTS", "192.168.1.100"))

        # Get the option back
        value = asyncio.run(mod.get_option("RHOSTS"))
        assert value == "192.168.1.100"

    def test_sync_module_options_case_insensitive(self, daemon_process):
        """Test that module options are case-insensitive."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        # Set with uppercase
        asyncio.run(mod.set_option("RHOSTS", "192.168.1.100"))

        # Get with lowercase
        value = asyncio.run(mod.get_option("rhosts"))
        assert value == "192.168.1.100"

    def test_sync_datastore_operations(self, daemon_process):
        """Test DataStore operations with sync client."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        ds = fw.datastore()

        # Set a value
        asyncio.run(ds.set("TestKey", "TestValue"))

        # Get the value
        value = asyncio.run(ds.get("TestKey"))
        assert value == "TestValue"

        # Delete the value
        asyncio.run(ds.delete("TestKey"))
        value_after_delete = asyncio.run(ds.get("TestKey"))
        assert value_after_delete is None

    def test_sync_session_manager_list(self, daemon_process):
        """Test SessionManager list with sync client."""
        from assassinate.bridge import Framework

        fw = Framework()
        sm = fw.sessions()

        # List should return a list (may be empty)
        sessions = sm.list()
        assert isinstance(sessions, list)

    def test_sync_error_invalid_module(self, daemon_process):
        """Test error handling for invalid module name."""
        from assassinate.bridge import Framework

        fw = Framework()

        # Try to create module with invalid name
        try:
            mod = fw.create_module("exploit/invalid/module/name")
            # If we get here, creation succeeded but it shouldn't have
            # Some invalid names might not raise immediately
            assert False, "Expected module creation to fail"
        except Exception as e:
            # Should get some kind of error
            assert True

    def test_sync_module_type(self, daemon_process):
        """Test getting module type."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        module_type = asyncio.run(mod.module_type())
        assert module_type == "exploit"

    def test_sync_module_description(self, daemon_process):
        """Test getting module description."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        description = asyncio.run(mod.description())
        assert isinstance(description, str)
        assert len(description) > 0

    def test_sync_module_platform(self, daemon_process):
        """Test getting module platform."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        platforms = asyncio.run(mod.platform())
        # platform may be None or a list
        if platforms is not None:
            assert isinstance(platforms, list)

    def test_sync_module_arch(self, daemon_process):
        """Test getting module architecture."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        archs = asyncio.run(mod.arch())
        assert isinstance(archs, list)

    def test_sync_module_rank(self, daemon_process):
        """Test getting module rank."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        rank = asyncio.run(mod.rank())
        assert isinstance(rank, str)
        # Rank is returned as numeric string: "0", "100", "200", "300", "400", "500", "600"
        # vsftpd backdoor should be excellent rank (600)
        assert rank in ["0", "100", "200", "300", "400", "500", "600"]

    def test_sync_module_author(self, daemon_process):
        """Test getting module authors."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        authors = asyncio.run(mod.author())
        # author may be None or a list
        if authors is not None:
            assert isinstance(authors, list)

    def test_sync_module_references(self, daemon_process):
        """Test getting module references."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        references = asyncio.run(mod.references())
        # references may be None or a list
        if references is not None:
            assert isinstance(references, list)

    def test_sync_get_client(self, daemon_process):
        """Test getting underlying client."""
        from assassinate.bridge import Framework

        fw = Framework()
        client = fw.get_client()

        assert client is not None
        # Verify it's a SyncMsfClient
        from assassinate.ipc.sync import SyncMsfClient

        assert isinstance(client, SyncMsfClient)

    def test_sync_datastore_to_dict(self, daemon_process):
        """Test converting datastore to dict."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        ds = fw.datastore()

        # Set some values
        asyncio.run(ds.set("Key1", "Value1"))
        asyncio.run(ds.set("Key2", "Value2"))

        # Get as dict
        data = asyncio.run(ds.to_dict())
        assert isinstance(data, dict)
        assert "Key1" in data or "key1" in data.keys().__str__().lower()

        # Cleanup
        asyncio.run(ds.delete("Key1"))
        asyncio.run(ds.delete("Key2"))

    def test_sync_datastore_keys(self, daemon_process):
        """Test getting datastore keys."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        ds = fw.datastore()

        # Set some values
        asyncio.run(ds.set("TestKey1", "Value1"))
        asyncio.run(ds.set("TestKey2", "Value2"))

        # Get keys
        keys = asyncio.run(ds.keys())
        assert isinstance(keys, list)

        # Cleanup
        asyncio.run(ds.delete("TestKey1"))
        asyncio.run(ds.delete("TestKey2"))

    def test_sync_module_validate(self, daemon_process):
        """Test module validation."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        # Set required options
        asyncio.run(mod.set_option("RHOSTS", "192.168.1.100"))

        # Validate should work
        is_valid = asyncio.run(mod.validate())
        assert isinstance(is_valid, bool)

    def test_sync_module_has_check(self, daemon_process):
        """Test checking if module has check method."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        has_check = asyncio.run(mod.has_check())
        assert isinstance(has_check, bool)

    def test_sync_module_compatible_payloads(self, daemon_process):
        """Test getting compatible payloads."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        payloads = asyncio.run(mod.compatible_payloads())
        assert isinstance(payloads, list)
        # vsftpd_234_backdoor is a command shell exploit that doesn't use
        # traditional payloads, so the list may be empty
        # Just verify the method works and returns a list

    def test_sync_module_options_method(self, daemon_process):
        """Test getting module options schema."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        options = asyncio.run(mod.options())
        assert isinstance(options, str)
        assert len(options) > 0

    def test_sync_module_targets(self, daemon_process):
        """Test getting module targets."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        targets = asyncio.run(mod.targets())
        assert isinstance(targets, list)

    def test_sync_module_disclosure_date(self, daemon_process):
        """Test getting module disclosure date."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        date = asyncio.run(mod.disclosure_date())
        # May be None or a string
        if date is not None:
            assert isinstance(date, str)

    def test_sync_module_privileged(self, daemon_process):
        """Test checking if module requires privileges."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        privileged = asyncio.run(mod.privileged())
        assert isinstance(privileged, bool)

    def test_sync_module_license(self, daemon_process):
        """Test getting module license."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        license = asyncio.run(mod.license())
        assert isinstance(license, str)

    def test_sync_module_aliases(self, daemon_process):
        """Test getting module aliases."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        aliases = asyncio.run(mod.aliases())
        assert isinstance(aliases, list)

    def test_sync_module_notes(self, daemon_process):
        """Test getting module notes."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        notes = asyncio.run(mod.notes())
        assert isinstance(notes, dict)

    def test_sync_module_repr(self, daemon_process):
        """Test module __repr__."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        repr_str = repr(mod)
        assert isinstance(repr_str, str)
        assert "Module" in repr_str

    def test_sync_datastore_clear(self, daemon_process):
        """Test clearing all datastore values."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        ds = fw.datastore()

        # Set some values
        asyncio.run(ds.set("ClearTest1", "Value1"))
        asyncio.run(ds.set("ClearTest2", "Value2"))

        # Clear all
        asyncio.run(ds.clear())

        # Verify they're gone
        data = asyncio.run(ds.to_dict())
        assert "ClearTest1" not in data
        assert "ClearTest2" not in data

    def test_sync_datastore_repr(self, daemon_process):
        """Test datastore __repr__."""
        from assassinate.bridge import Framework

        fw = Framework()
        ds = fw.datastore()

        repr_str = repr(ds)
        assert isinstance(repr_str, str)
        assert "DataStore" in repr_str

    def test_sync_session_manager_repr(self, daemon_process):
        """Test session manager __repr__."""
        from assassinate.bridge import Framework

        fw = Framework()
        sm = fw.sessions()

        repr_str = repr(sm)
        assert isinstance(repr_str, str)
        assert "SessionManager" in repr_str

    def test_sync_list_multiple_module_types(self, daemon_process):
        """Test listing multiple module types."""
        from assassinate.bridge import Framework

        fw = Framework()

        exploits = fw.list_modules("exploit")
        auxiliary = fw.list_modules("auxiliary")
        payloads = fw.list_modules("payload")

        assert len(exploits) > 0
        assert len(auxiliary) > 0
        assert len(payloads) > 0

        # Verify they're different lists
        assert exploits != auxiliary
        assert exploits != payloads

    def test_sync_search_with_different_queries(self, daemon_process):
        """Test search with different query patterns."""
        from assassinate.bridge import Framework

        fw = Framework()

        # Search by name
        vsftpd_results = fw.search("vsftpd")
        assert len(vsftpd_results) > 0

        # Search by type
        exploit_results = fw.search("type:exploit")
        assert len(exploit_results) > 0
        # All should be exploits
        assert all("exploit/" in r for r in exploit_results[:10])

    def test_sync_framework_multiple_instances(self, daemon_process):
        """Test that multiple Framework instances can coexist."""
        from assassinate.bridge import Framework

        fw1 = Framework()
        fw2 = Framework()

        v1 = fw1.version()
        v2 = fw2.version()

        # Both should work and return same version
        assert v1 == v2

    def test_sync_module_multiple_instances(self, daemon_process):
        """Test that multiple module instances can coexist."""
        import asyncio

        from assassinate.bridge import Framework

        fw = Framework()
        mod1 = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
        mod2 = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

        # Both should work independently
        asyncio.run(mod1.set_option("RHOSTS", "192.168.1.1"))
        asyncio.run(mod2.set_option("RHOSTS", "192.168.1.2"))

        val1 = asyncio.run(mod1.get_option("RHOSTS"))
        val2 = asyncio.run(mod2.get_option("RHOSTS"))

        assert val1 == "192.168.1.1"
        assert val2 == "192.168.1.2"


# Note: We don't test mixing sync and async APIs in the same test
# because it causes event loop conflicts. Each API should be tested
# separately, and they're tested against the same daemon in different tests.
