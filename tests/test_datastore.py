"""Tests for DataStore functionality (framework and module level)."""

import pytest


@pytest.mark.integration
class TestFrameworkDataStore:
    """Tests for framework-level datastore operations."""

    async def test_framework_set_and_get_option(self, client):
        """Test setting and getting a framework option."""
        await client.framework_set_option("TEST_KEY", "test_value")
        value = await client.framework_get_option("TEST_KEY")
        assert value == "test_value"

    async def test_framework_get_nonexistent_option(self, client):
        """Test getting a nonexistent option returns None."""
        value = await client.framework_get_option("NONEXISTENT_KEY_12345")
        assert value is None or value == ""

    async def test_framework_overwrite_option(self, client):
        """Test overwriting an existing option."""
        await client.framework_set_option("OVERWRITE_KEY", "value1")
        await client.framework_set_option("OVERWRITE_KEY", "value2")
        value = await client.framework_get_option("OVERWRITE_KEY")
        assert value == "value2"

    async def test_framework_datastore_to_dict(self, client):
        """Test getting all framework datastore as dict."""
        # Set some test values
        await client.framework_set_option("DICT_TEST_1", "val1")
        await client.framework_set_option("DICT_TEST_2", "val2")

        datastore = await client.framework_datastore_to_dict()
        assert isinstance(datastore, dict)
        assert "DICT_TEST_1" in datastore or "dict_test_1" in datastore.lower()
        assert "DICT_TEST_2" in datastore or "dict_test_2" in datastore.lower()

    async def test_framework_delete_option(self, client):
        """Test deleting a framework option."""
        await client.framework_set_option("DELETE_KEY", "delete_value")
        await client.framework_delete_option("DELETE_KEY")
        value = await client.framework_get_option("DELETE_KEY")
        assert value is None or value == ""

    async def test_framework_clear_datastore(self, client):
        """Test clearing all framework datastore options."""
        # Set some values
        await client.framework_set_option("CLEAR_TEST_1", "val1")
        await client.framework_set_option("CLEAR_TEST_2", "val2")

        # Clear datastore
        await client.framework_clear_datastore()

        # Verify cleared
        val1 = await client.framework_get_option("CLEAR_TEST_1")
        val2 = await client.framework_get_option("CLEAR_TEST_2")
        assert (val1 is None or val1 == "") and (val2 is None or val2 == "")


@pytest.mark.integration
class TestModuleDataStore:
    """Tests for module-level datastore operations."""

    async def test_module_datastore_to_dict(self, test_module, client):
        """Test getting module datastore as dict."""
        # Set some options
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.1")
        await client.module_set_option(test_module, "RPORT", "21")

        datastore = await client.module_datastore_to_dict(test_module)
        assert isinstance(datastore, dict)
        # Module datastore should include options we set
        assert len(datastore) > 0

    async def test_module_set_and_get_via_datastore(self, test_module, client):
        """Test module options work through datastore."""
        await client.module_set_option(test_module, "RHOSTS", "10.0.0.1")
        value = await client.module_get_option(test_module, "RHOSTS")
        assert value == "10.0.0.1"

    async def test_module_delete_option(self, test_module, client):
        """Test deleting a module option."""
        # Set an option
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.100")

        # Delete it
        await client.module_delete_option(test_module, "RHOSTS")

        # Verify deleted
        value = await client.module_get_option(test_module, "RHOSTS")
        assert value is None or value == ""

    async def test_module_clear_datastore(self, test_module, client):
        """Test clearing all module datastore options."""
        # Set multiple options
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.1")
        await client.module_set_option(test_module, "RPORT", "2121")

        # Clear datastore
        await client.module_clear_datastore(test_module)

        # Verify cleared
        rhosts = await client.module_get_option(test_module, "RHOSTS")
        rport = await client.module_get_option(test_module, "RPORT")
        assert (rhosts is None or rhosts == "") and (
            rport is None or rport == ""
        )

    async def test_module_datastore_independent_from_framework(
        self, test_module, client
    ):
        """Test module datastore is independent from framework."""
        # Set framework option
        await client.framework_set_option(
            "INDEPENDENCE_TEST", "framework_value"
        )

        # Set module option with different value
        await client.module_set_option(
            test_module, "INDEPENDENCE_TEST", "module_value"
        )

        # Verify they're independent
        fw_val = await client.framework_get_option("INDEPENDENCE_TEST")
        mod_val = await client.module_get_option(
            test_module, "INDEPENDENCE_TEST"
        )

        assert fw_val == "framework_value"
        assert mod_val == "module_value"
