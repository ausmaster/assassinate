"""Tests for PluginManager functionality.

Note: These tests verify the IPC layer works correctly. Loading real plugins
requires plugin files which may not be available in the test environment.
"""

import pytest


@pytest.mark.integration
class TestPluginList:
    """Tests for listing plugins."""

    async def test_list_plugins_returns_list(self, client):
        """Test that listing plugins returns a list."""
        plugins = await client.plugins_list()
        assert isinstance(plugins, list)
        # May be empty if no plugins loaded
        assert plugins is not None

    async def test_list_plugins_type(self, client):
        """Test that plugin names are strings."""
        plugins = await client.plugins_list()
        for plugin in plugins:
            assert isinstance(plugin, str)


@pytest.mark.integration
class TestPluginLoad:
    """Tests for loading plugins."""

    async def test_load_nonexistent_plugin_fails(self, client):
        """Test that loading a nonexistent plugin fails."""
        # Trying to load a non-existent plugin should raise an error
        with pytest.raises(Exception):  # Will raise RemoteError
            await client.plugins_load("/nonexistent/plugin/path.rb")

    async def test_load_with_invalid_path(self, client):
        """Test that loading with invalid path fails."""
        with pytest.raises(Exception):
            await client.plugins_load("")


@pytest.mark.integration
class TestPluginUnload:
    """Tests for unloading plugins."""

    async def test_unload_nonexistent_plugin(self, client):
        """Test that unloading a nonexistent plugin returns False."""
        result = await client.plugins_unload("nonexistent_plugin_12345")
        assert isinstance(result, bool)
        # Should return False for nonexistent plugin
        assert result is False

    async def test_unload_with_empty_name(self, client):
        """Test that unloading with empty name returns False."""
        result = await client.plugins_unload("")
        assert isinstance(result, bool)
        assert result is False


@pytest.mark.integration
class TestPluginWorkflow:
    """Tests for complete plugin workflows."""

    async def test_operations_dont_crash(self, client):
        """Test that plugin operations handle edge cases gracefully."""
        # These should not raise exceptions
        plugins = await client.plugins_list()
        assert isinstance(plugins, list)

        # Unload operations should return False for invalid names
        result = await client.plugins_unload("fake_plugin")
        assert isinstance(result, bool)
        assert result is False

    async def test_list_after_operations(self, client):
        """Test that list works after other operations."""
        # Try to unload a fake plugin
        await client.plugins_unload("fake_plugin_xyz")

        # List should still work
        plugins = await client.plugins_list()
        assert isinstance(plugins, list)
