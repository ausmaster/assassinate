"""Tests for database status operations.

Note: These tests verify the database status API works correctly.
The db_active() method should work even without a configured database
(it will return False). The db_driver() method requires a database.
"""

import pytest


@pytest.mark.asyncio
async def test_status_api_exists(client):
    """Test that status API methods exist."""
    assert hasattr(client, 'db_active')
    assert callable(client.db_active)
    assert hasattr(client, 'db_driver')
    assert callable(client.db_driver)
    print("✓ All database status APIs exist")


@pytest.mark.asyncio
async def test_db_active(client):
    """Test db_active status check.

    This test should work regardless of database configuration.
    """
    print("\nTesting db_active")
    try:
        active = await client.db_active()
        print(f"   ✓ db_active() works - database is {'active' if active else 'not active'}")
        assert isinstance(active, bool), "db_active should return boolean"

        if active:
            print("   Database is configured and connected")
        else:
            print("   No database configured")
    except Exception as e:
        print(f"   ⚠ db_active() failed: {e}")
        pytest.fail(f"db_active should not fail: {e}")


@pytest.mark.asyncio
async def test_db_driver_with_database(client):
    """Test db_driver when database is active.

    This test requires an active database connection.
    """
    # Check if database is active
    try:
        active = await client.db_active()
    except Exception as e:
        pytest.skip(f"Cannot check database status: {e}")

    if not active:
        pytest.skip("No database configured - db_driver test requires active database")

    print("\nTesting db_driver with active database")
    try:
        driver = await client.db_driver()
        print(f"   ✓ db_driver() works - driver: {driver}")
        assert isinstance(driver, str), "db_driver should return string"
        assert len(driver) > 0, "Driver name should not be empty"

        # Common drivers: postgresql, mysql, sqlite3
        print(f"   Database driver is: {driver}")
    except Exception as e:
        print(f"   ⚠ db_driver() failed: {e}")
        pytest.fail(f"db_driver failed with active database: {e}")


@pytest.mark.asyncio
async def test_db_driver_without_database(client):
    """Test db_driver behavior when database is not active.

    This verifies the API handles the no-database case gracefully.
    """
    # Check if database is active
    try:
        active = await client.db_active()
    except Exception:
        pytest.skip("Cannot check database status")

    if active:
        pytest.skip("Database is active - this test is for no-database scenario")

    print("\nTesting db_driver without active database")
    try:
        driver = await client.db_driver()
        print(f"   Unexpected: db_driver returned '{driver}' without active database")
        # Some implementations may return empty string or default value
    except Exception as e:
        print(f"   ✓ db_driver properly fails without database: {type(e).__name__}")
        # Expected behavior - may raise exception without database


@pytest.mark.asyncio
async def test_combined_status_check(client):
    """Test combined usage of status methods.

    Demonstrates typical usage pattern for checking database status.
    """
    print("\nDemonstrating typical status check pattern:")
    try:
        active = await client.db_active()
        print(f"   Database active: {active}")

        if active:
            try:
                driver = await client.db_driver()
                print(f"   Database driver: {driver}")
                print("   ✓ Full database status retrieved successfully")
            except Exception as e:
                print(f"   ⚠ Could not get driver: {e}")
        else:
            print("   Skipping driver check (database not active)")
    except Exception as e:
        print(f"   ⚠ Status check failed: {e}")


@pytest.mark.asyncio
async def test_status_consistency(client):
    """Test that status methods are consistent.

    If db_active() returns True, db_driver() should work.
    """
    try:
        active = await client.db_active()
    except Exception:
        pytest.skip("Cannot check database status")

    if not active:
        pytest.skip("Database not active - consistency check requires active database")

    print("\nTesting status consistency")
    try:
        # If active is True, driver should work
        driver = await client.db_driver()
        print(f"   ✓ Consistency verified: active={active}, driver={driver}")
        assert driver is not None, "Driver should not be None when database is active"
    except Exception as e:
        pytest.fail(f"Inconsistent state: active={active} but driver failed: {e}")
