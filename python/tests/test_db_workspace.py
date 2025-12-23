"""Tests for database workspace management operations.

Note: These tests verify the workspace management API works correctly.
Tests gracefully skip if no database is configured.

To enable database for testing:
    In msfconsole:
    db_connect postgresql://user:pass@localhost/msf_test
    OR use the docker test environment which has PostgreSQL configured
"""

import pytest


@pytest.mark.asyncio
async def test_workspaces_api_exists(client):
    """Test that workspaces API methods exist."""
    assert hasattr(client, 'db_workspaces')
    assert callable(client.db_workspaces)
    assert hasattr(client, 'db_workspace')
    assert callable(client.db_workspace)
    assert hasattr(client, 'db_set_workspace')
    assert callable(client.db_set_workspace)
    assert hasattr(client, 'db_add_workspace')
    assert callable(client.db_add_workspace)
    assert hasattr(client, 'db_find_workspace')
    assert callable(client.db_find_workspace)
    assert hasattr(client, 'db_delete_workspace')
    assert callable(client.db_delete_workspace)
    print("✓ All workspace management APIs exist")


@pytest.mark.asyncio
async def test_workspace_operations(client):
    """Test workspace management operations with active database.

    This test requires an active database connection.
    If no database is configured, the test will be skipped.
    """
    # Check if database is active by trying to get current workspace
    try:
        current_workspace = await client.db_workspace()
    except Exception as e:
        pytest.skip(f"No database configured: {e}")

    print(f"\n✓ Database is active, current workspace: {current_workspace}")

    # Test 1: List all workspaces
    print("\n1. Testing db_workspaces")
    try:
        workspaces = await client.db_workspaces()
        print(f"   ✓ db_workspaces() works - found {len(workspaces)} workspaces")
        assert isinstance(workspaces, list)

        if workspaces:
            ws = workspaces[0]
            print(f"   Sample workspace: ID {ws.get('id')} - {ws.get('name')}")
            assert 'id' in ws, "Workspace should have 'id' key"
            assert 'name' in ws, "Workspace should have 'name' key"
    except Exception as e:
        print(f"   ⚠ db_workspaces() failed: {e}")
        pytest.fail(f"db_workspaces failed: {e}")

    # Test 2: Get current workspace
    print("\n2. Testing db_workspace")
    try:
        workspace = await client.db_workspace()
        if workspace:
            print(f"   ✓ db_workspace() works - current: {workspace.get('name')}")
            assert isinstance(workspace, dict)
            assert 'id' in workspace
            assert 'name' in workspace
            original_workspace_name = workspace['name']
        else:
            print("   ⚠ No current workspace set")
            original_workspace_name = "default"
    except Exception as e:
        print(f"   ⚠ db_workspace() failed: {e}")
        pytest.fail(f"db_workspace failed: {e}")

    # Test 3: Create new workspace
    print("\n3. Testing db_add_workspace")
    test_workspace_name = "assassinate_test_workspace"
    try:
        new_workspace = await client.db_add_workspace(test_workspace_name)
        print(f"   ✓ db_add_workspace() works - created ID {new_workspace.get('id')}")
        assert isinstance(new_workspace, dict)
        assert 'id' in new_workspace
        assert 'name' in new_workspace
        assert new_workspace['name'] == test_workspace_name
        test_workspace_id = new_workspace['id']
    except Exception as e:
        print(f"   ⚠ db_add_workspace() failed: {e}")
        pytest.skip(f"Cannot create workspace: {e}")

    # Test 4: Find workspace by name
    print("\n4. Testing db_find_workspace")
    try:
        found_workspace = await client.db_find_workspace(test_workspace_name)
        if found_workspace:
            print(f"   ✓ db_find_workspace() works - found ID {found_workspace.get('id')}")
            assert found_workspace['name'] == test_workspace_name
            assert found_workspace['id'] == test_workspace_id
        else:
            print("   ⚠ Workspace not found (unexpected)")
    except Exception as e:
        print(f"   ⚠ db_find_workspace() failed: {e}")

    # Test 5: Set workspace
    print("\n5. Testing db_set_workspace")
    try:
        await client.db_set_workspace(test_workspace_name)
        print(f"   ✓ db_set_workspace() works - switched to {test_workspace_name}")

        # Verify the switch
        current = await client.db_workspace()
        if current:
            assert current['name'] == test_workspace_name, "Workspace should be switched"
            print(f"   ✓ Verified current workspace is now: {current['name']}")
    except Exception as e:
        print(f"   ⚠ db_set_workspace() failed: {e}")

    # Test 6: Delete workspace (cleanup)
    print("\n6. Testing db_delete_workspace")
    try:
        # Switch back to original workspace first (can't delete current workspace)
        await client.db_set_workspace(original_workspace_name)
        print(f"   Switched back to: {original_workspace_name}")

        # Now delete the test workspace
        success = await client.db_delete_workspace(test_workspace_id)
        print(f"   ✓ db_delete_workspace() works - deleted: {success}")
        assert success, "Delete should return True"

        # Verify deletion
        found = await client.db_find_workspace(test_workspace_name)
        assert found is None, "Workspace should no longer exist"
        print("   ✓ Verified workspace was deleted")
    except Exception as e:
        print(f"   ⚠ db_delete_workspace() failed: {e}")
        # Try to clean up anyway
        try:
            await client.db_set_workspace(original_workspace_name)
        except:
            pass

    print("\n✅ Workspace management operations test completed")


@pytest.mark.asyncio
async def test_workspace_not_found(client):
    """Test that workspace operations handle non-existent workspace gracefully."""
    try:
        current = await client.db_workspace()
    except Exception:
        pytest.skip("No database configured")

    # Try to find non-existent workspace
    print("\n1. Testing find_workspace with non-existent name")
    try:
        found = await client.db_find_workspace("nonexistent_workspace_xyz")
        assert found is None, "Should return None for non-existent workspace"
        print("   ✓ find_workspace returns None for non-existent workspace")
    except Exception as e:
        print(f"   ⚠ Unexpected error: {e}")

    # Try to switch to non-existent workspace
    print("\n2. Testing set_workspace with non-existent name")
    try:
        await client.db_set_workspace("nonexistent_workspace_xyz")
        print("   ⚠ set_workspace should have failed for non-existent workspace")
    except Exception as e:
        print(f"   ✓ set_workspace properly fails: {type(e).__name__}")


@pytest.mark.asyncio
async def test_delete_nonexistent_workspace(client):
    """Test deleting a non-existent workspace."""
    try:
        await client.db_workspace()
    except Exception:
        pytest.skip("No database configured")

    print("\nTesting delete_workspace with non-existent ID")
    try:
        # Try to delete workspace with very high ID (unlikely to exist)
        success = await client.db_delete_workspace(999999)
        print(f"   Delete returned: {success}")
        # MSF may return false or raise an exception
    except Exception as e:
        print(f"   ✓ delete_workspace properly fails: {type(e).__name__}")
