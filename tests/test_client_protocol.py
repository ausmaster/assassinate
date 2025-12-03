"""Tests for client protocol and call_client_method utility.

Tests that call_client_method correctly handles both async (MsfClient)
and sync (SyncMsfClient) clients, and that Module class works with both.
"""

import asyncio

import pytest


@pytest.mark.integration
class TestClientProtocol:
    """Tests for client protocol abstraction."""

    async def test_call_client_method_with_async_client(self, client):
        """Test call_client_method with async MsfClient."""
        from assassinate.bridge.client_utils import call_client_method
        from assassinate.ipc import MsfClient

        # Verify we have an async client
        assert isinstance(client, MsfClient)

        # Call a method that returns a coroutine
        result = await call_client_method(client, "framework_version")

        assert isinstance(result, dict)
        assert "version" in result

    def test_call_client_method_with_sync_client(self, daemon_process):
        """Test call_client_method with sync SyncMsfClient."""

        from assassinate.bridge.client_utils import call_client_method
        from assassinate.ipc.sync import SyncMsfClient

        # Create a sync client
        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            # Call a method - even though it's sync, we can still await the result
            result = asyncio.run(
                call_client_method(sync_client, "framework_version")
            )

            assert isinstance(result, dict)
            assert "version" in result
        finally:
            sync_client.disconnect()

    async def test_module_with_async_client(self, client):
        """Test Module class with async MsfClient."""
        from assassinate.bridge.modules import Module
        from assassinate.ipc import MsfClient

        # Verify we have an async client
        assert isinstance(client, MsfClient)

        # Create a module
        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )

        # Create Module instance
        mod = Module(module_id, client)

        # Test async methods work
        name = await mod.name()
        assert isinstance(name, str)

        fullname = await mod.fullname()
        assert fullname == "exploit/unix/ftp/vsftpd_234_backdoor"

        # Set and get an option
        await mod.set_option("RHOSTS", "192.168.1.100")
        value = await mod.get_option("RHOSTS")
        assert value == "192.168.1.100"

        # Cleanup
        await client.delete_module(module_id)

    def test_module_with_sync_client(self, daemon_process):
        """Test Module class with sync SyncMsfClient."""

        from assassinate.bridge.modules import Module
        from assassinate.ipc.sync import SyncMsfClient

        # Create a sync client
        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            # Create a module
            module_id = sync_client.create_module(
                "exploit/unix/ftp/vsftpd_234_backdoor"
            )

            # Create Module instance
            mod = Module(module_id, sync_client)

            # Test methods work - we still use await, but the underlying
            # client call will be sync
            name = asyncio.run(mod.name())
            assert isinstance(name, str)

            fullname = asyncio.run(mod.fullname())
            assert fullname == "exploit/unix/ftp/vsftpd_234_backdoor"

            # Set and get an option
            asyncio.run(mod.set_option("RHOSTS", "192.168.1.100"))
            value = asyncio.run(mod.get_option("RHOSTS"))
            assert value == "192.168.1.100"

            # Cleanup
            sync_client.delete_module(module_id)
        finally:
            sync_client.disconnect()

    async def test_module_info_with_async_client(self, client):
        """Test Module info methods with async client."""
        from assassinate.bridge.modules import Module

        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        mod = Module(module_id, client)

        try:
            # Test various info methods
            module_type = await mod.module_type()
            assert module_type == "exploit"

            description = await mod.description()
            assert isinstance(description, str)
            assert len(description) > 0

            rank = await mod.rank()
            assert isinstance(rank, str)

            platform = await mod.platform()
            if platform is not None:
                assert isinstance(platform, list)

            arch = await mod.arch()
            assert isinstance(arch, list)

            authors = await mod.author()
            if authors is not None:
                assert isinstance(authors, list)

            references = await mod.references()
            if references is not None:
                assert isinstance(references, list)
        finally:
            await client.delete_module(module_id)

    def test_module_info_with_sync_client(self, daemon_process):
        """Test Module info methods with sync client."""

        from assassinate.bridge.modules import Module
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            module_id = sync_client.create_module(
                "exploit/unix/ftp/vsftpd_234_backdoor"
            )
            mod = Module(module_id, sync_client)

            # Test various info methods
            module_type = asyncio.run(mod.module_type())
            assert module_type == "exploit"

            description = asyncio.run(mod.description())
            assert isinstance(description, str)
            assert len(description) > 0

            rank = asyncio.run(mod.rank())
            assert isinstance(rank, str)

            platform = asyncio.run(mod.platform())
            if platform is not None:
                assert isinstance(platform, list)

            arch = asyncio.run(mod.arch())
            assert isinstance(arch, list)

            authors = asyncio.run(mod.author())
            if authors is not None:
                assert isinstance(authors, list)

            references = asyncio.run(mod.references())
            if references is not None:
                assert isinstance(references, list)

            # Cleanup
            sync_client.delete_module(module_id)
        finally:
            sync_client.disconnect()

    async def test_datastore_with_async_client(self, client):
        """Test DataStore with async client."""
        from assassinate.bridge.datastore import DataStore

        ds = DataStore(client)

        # Test set/get/delete
        await ds.set("ProtocolTestKey", "TestValue")
        value = await ds.get("ProtocolTestKey")
        assert value == "TestValue"

        await ds.delete("ProtocolTestKey")
        value = await ds.get("ProtocolTestKey")
        assert value is None

    def test_datastore_with_sync_client(self, daemon_process):
        """Test DataStore with sync client."""

        from assassinate.bridge.datastore import DataStore
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            ds = DataStore(sync_client)

            # Test set/get/delete
            asyncio.run(ds.set("ProtocolTestKey", "TestValue"))
            value = asyncio.run(ds.get("ProtocolTestKey"))
            assert value == "TestValue"

            asyncio.run(ds.delete("ProtocolTestKey"))
            value = asyncio.run(ds.get("ProtocolTestKey"))
            assert value is None
        finally:
            sync_client.disconnect()

    async def test_module_datastore_with_async_client(self, client):
        """Test Module-specific DataStore with async client."""
        from assassinate.bridge.datastore import DataStore

        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )

        try:
            # Create module-specific datastore
            ds = DataStore(client, module_id)

            # Test operations
            await ds.set("RHOSTS", "192.168.1.100")
            value = await ds.get("RHOSTS")
            assert value == "192.168.1.100"

            # Get as dict
            data = await ds.to_dict()
            assert isinstance(data, dict)

            # Get keys
            keys = await ds.keys()
            assert isinstance(keys, list)
        finally:
            await client.delete_module(module_id)

    def test_module_datastore_with_sync_client(self, daemon_process):
        """Test Module-specific DataStore with sync client."""

        from assassinate.bridge.datastore import DataStore
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            module_id = sync_client.create_module(
                "exploit/unix/ftp/vsftpd_234_backdoor"
            )

            # Create module-specific datastore
            ds = DataStore(sync_client, module_id)

            # Test operations
            asyncio.run(ds.set("RHOSTS", "192.168.1.100"))
            value = asyncio.run(ds.get("RHOSTS"))
            assert value == "192.168.1.100"

            # Get as dict
            data = asyncio.run(ds.to_dict())
            assert isinstance(data, dict)

            # Get keys
            keys = asyncio.run(ds.keys())
            assert isinstance(keys, list)

            # Cleanup
            sync_client.delete_module(module_id)
        finally:
            sync_client.disconnect()

    async def test_call_client_method_with_args(self, client):
        """Test call_client_method with arguments."""
        from assassinate.bridge.client_utils import call_client_method

        # Test with positional args
        modules = await call_client_method(client, "list_modules", "exploit")
        assert isinstance(modules, list)
        assert len(modules) > 0

        # Test with search
        results = await call_client_method(client, "search", "vsftpd")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_call_client_method_sync_with_args(self, daemon_process):
        """Test call_client_method with sync client and arguments."""

        from assassinate.bridge.client_utils import call_client_method
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            # Test with positional args
            modules = asyncio.run(
                call_client_method(sync_client, "list_modules", "exploit")
            )
            assert isinstance(modules, list)
            assert len(modules) > 0

            # Test with search
            results = asyncio.run(
                call_client_method(sync_client, "search", "vsftpd")
            )
            assert isinstance(results, list)
            assert len(results) > 0
        finally:
            sync_client.disconnect()

    async def test_module_options_operations_async(self, client):
        """Test module option operations with async client."""
        from assassinate.bridge.modules import Module

        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        mod = Module(module_id, client)

        try:
            # Test set/get
            await mod.set_option("RHOSTS", "10.0.0.1")
            value = await mod.get_option("RHOSTS")
            assert value == "10.0.0.1"

            # Test case insensitivity
            await mod.set_option("rhost", "10.0.0.2")
            value = await mod.get_option("RHOSTS")
            assert value == "10.0.0.2"

            # Test validate
            is_valid = await mod.validate()
            assert isinstance(is_valid, bool)
        finally:
            await client.delete_module(module_id)

    def test_module_options_operations_sync(self, daemon_process):
        """Test module option operations with sync client."""

        from assassinate.bridge.modules import Module
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            module_id = sync_client.create_module(
                "exploit/unix/ftp/vsftpd_234_backdoor"
            )
            mod = Module(module_id, sync_client)

            # Test set/get
            asyncio.run(mod.set_option("RHOSTS", "10.0.0.1"))
            value = asyncio.run(mod.get_option("RHOSTS"))
            assert value == "10.0.0.1"

            # Test case insensitivity
            asyncio.run(mod.set_option("rhost", "10.0.0.2"))
            value = asyncio.run(mod.get_option("RHOSTS"))
            assert value == "10.0.0.2"

            # Test validate
            is_valid = asyncio.run(mod.validate())
            assert isinstance(is_valid, bool)

            # Cleanup
            sync_client.delete_module(module_id)
        finally:
            sync_client.disconnect()


@pytest.mark.integration
class TestClientTypeDetection:
    """Tests for automatic client type detection."""

    async def test_async_client_returns_coroutine(self, client):
        """Verify async client methods return coroutines."""
        import inspect

        from assassinate.ipc import MsfClient

        assert isinstance(client, MsfClient)

        # Call a method - should return a coroutine
        result = client.framework_version()
        assert inspect.iscoroutine(result)

        # Consume the coroutine
        await result

    def test_sync_client_returns_value(self, daemon_process):
        """Verify sync client methods return values directly."""
        import inspect

        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            # Call a method - should return value directly
            result = sync_client.framework_version()
            assert not inspect.iscoroutine(result)
            assert isinstance(result, dict)
        finally:
            sync_client.disconnect()

    async def test_call_client_method_detects_async(self, client):
        """Test that call_client_method detects async client correctly."""
        import inspect

        from assassinate.bridge.client_utils import call_client_method

        # The result of call_client_method should always be a coroutine
        result = call_client_method(client, "framework_version")
        assert inspect.iscoroutine(result)

        # Await it
        value = await result
        assert isinstance(value, dict)

    def test_call_client_method_detects_sync(self, daemon_process):
        """Test that call_client_method detects sync client correctly."""
        import inspect

        from assassinate.bridge.client_utils import call_client_method
        from assassinate.ipc.sync import SyncMsfClient

        sync_client = SyncMsfClient()
        sync_client.connect()

        try:
            # The result of call_client_method should always be awaitable
            result = call_client_method(sync_client, "framework_version")
            assert inspect.iscoroutine(result)

            # Await it
            value = asyncio.run(result)
            assert isinstance(value, dict)
        finally:
            sync_client.disconnect()


# Note: These tests verify that the Module, DataStore, and other bridge classes
# work transparently with both async and sync clients via the call_client_method utility.
