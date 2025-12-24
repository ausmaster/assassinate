"""Tests for framework management operations."""

import pytest


@pytest.mark.asyncio
async def test_framework_module_stats(client):
    """Test getting module statistics."""
    print("\nTesting framework_module_stats")
    stats = await client.framework_module_stats()

    print(f"   ✓ Module stats retrieved: {stats}")

    # Verify expected keys
    expected_keys = {'exploits', 'auxiliary', 'post', 'encoders', 'nops', 'payloads', 'evasions'}
    assert set(stats.keys()) == expected_keys, f"Missing keys: {expected_keys - set(stats.keys())}"

    # Verify all values are integers
    for key, value in stats.items():
        assert isinstance(value, int), f"{key} should be integer, got {type(value)}"
        assert value >= 0, f"{key} count should be non-negative, got {value}"

    # Verify we have reasonable module counts
    assert stats['exploits'] > 0, "Should have exploits"
    assert stats['auxiliary'] > 0, "Should have auxiliary modules"
    assert stats['payloads'] > 0, "Should have payloads"

    print(f"   Exploits: {stats['exploits']}, Auxiliary: {stats['auxiliary']}, Payloads: {stats['payloads']}")


@pytest.mark.asyncio
async def test_framework_save(client):
    """Test saving framework configuration."""
    print("\nTesting framework_save")

    # Should not raise exception
    await client.framework_save()
    print("   ✓ Framework configuration saved successfully")


@pytest.mark.asyncio
async def test_framework_reload_modules(client):
    """Test reloading framework modules.

    Note: This is a slow operation that reloads all modules.
    """
    print("\nTesting framework_reload_modules")
    print("   (This may take 30+ seconds...)")

    stats = await client.framework_reload_modules()

    print(f"   ✓ Modules reloaded: {stats}")

    # Verify expected keys
    expected_keys = {'exploits', 'auxiliary', 'post', 'encoders', 'nops', 'payloads', 'evasions'}
    assert set(stats.keys()) == expected_keys, f"Missing keys: {expected_keys - set(stats.keys())}"

    # Verify we have module counts
    assert stats['exploits'] > 0, "Should have exploits after reload"
    assert stats['auxiliary'] > 0, "Should have auxiliary after reload"


@pytest.mark.asyncio
async def test_framework_add_module_path_invalid(client):
    """Test adding an invalid module path (should fail gracefully)."""
    print("\nTesting framework_add_module_path with invalid path")

    try:
        stats = await client.framework_add_module_path("/nonexistent/path")
        print(f"   Unexpected success: {stats}")
        # If it succeeds, stats should be all zeros
        total = sum(stats.values())
        assert total == 0, "Invalid path should load zero modules"
    except Exception as e:
        print(f"   ✓ Failed as expected: {type(e).__name__}")
        # Expected to fail


@pytest.mark.asyncio
async def test_stats_consistency(client):
    """Test that module_stats returns consistent results."""
    print("\nTesting stats consistency")

    stats1 = await client.framework_module_stats()
    stats2 = await client.framework_module_stats()

    # Should return same counts
    assert stats1 == stats2, "Stats should be consistent across calls"
    print("   ✓ Stats are consistent")
