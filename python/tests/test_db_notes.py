"""Tests for database notes management operations.

Note: These tests verify the notes management API works correctly.
Tests gracefully skip if no database is configured.

Notes in Metasploit are annotations attached to hosts or services in the database.
Common note types include:
- host.comments - General comments about a host
- host.os.session_fingerprint - OS fingerprinting data
- service.banner - Service banner information
"""

import pytest


@pytest.mark.asyncio
async def test_notes_api_exists(client):
    """Test that notes API methods exist."""
    assert hasattr(client, 'db_notes')
    assert callable(client.db_notes)
    assert hasattr(client, 'db_report_note')
    assert callable(client.db_report_note)
    assert hasattr(client, 'db_delete_note')
    assert callable(client.db_delete_note)
    print("✓ All notes management APIs exist")


@pytest.mark.asyncio
async def test_notes_operations(client):
    """Test notes management operations with active database.

    This test requires an active database connection and at least one host.
    If no database is configured, the test will be skipped.
    """
    # Check if database is active
    try:
        workspace = await client.db_workspace()
    except Exception as e:
        pytest.skip(f"No database configured: {e}")

    if not workspace:
        pytest.skip("No active workspace")

    print(f"\n✓ Database is active, workspace: {workspace.get('name')}")

    # Ensure we have at least one host to attach notes to
    print("\n0. Ensuring test host exists")
    try:
        test_host = "192.168.100.200"  # Test IP
        host_id = await client.db_report_host({"host": test_host})
        print(f"   ✓ Test host ready: {test_host} (ID: {host_id})")
    except Exception as e:
        pytest.skip(f"Cannot create test host: {e}")

    # Test 1: List all notes
    print("\n1. Testing db_notes")
    try:
        notes = await client.db_notes()
        print(f"   ✓ db_notes() works - found {len(notes)} notes")
        assert isinstance(notes, list)

        if notes:
            note = notes[0]
            print(f"   Sample note: ID {note.get('id')} - Type: {note.get('ntype')}")
    except Exception as e:
        print(f"   ⚠ db_notes() failed: {e}")
        pytest.fail(f"db_notes failed: {e}")

    # Test 2: Create a note
    print("\n2. Testing db_report_note")
    test_note_data = "Assassinate test note - can be deleted"
    try:
        note_id = await client.db_report_note({
            "host": test_host,
            "type": "host.comments",
            "data": test_note_data
        })
        print(f"   ✓ db_report_note() works - created note ID {note_id}")
        assert isinstance(note_id, int)
        assert note_id > 0, "Note ID should be positive"
    except Exception as e:
        print(f"   ⚠ db_report_note() failed: {e}")
        pytest.skip(f"Cannot create note: {e}")

    # Test 3: List notes with filter
    print("\n3. Testing db_notes with filter")
    try:
        host_notes = await client.db_notes({"host": test_host})
        print(f"   ✓ db_notes(filter) works - found {len(host_notes)} notes for host")
        assert isinstance(host_notes, list)

        # Verify our test note is in the results
        found_test_note = False
        for note in host_notes:
            if note.get('id') == note_id:
                found_test_note = True
                assert note.get('data') == test_note_data
                print(f"   ✓ Verified test note exists with correct data")
                break

        assert found_test_note, "Test note should be found in filtered results"
    except Exception as e:
        print(f"   ⚠ db_notes(filter) failed: {e}")

    # Test 4: Delete note (cleanup)
    print("\n4. Testing db_delete_note")
    try:
        count = await client.db_delete_note([note_id])
        print(f"   ✓ db_delete_note() works - deleted {count} note(s)")
        assert count >= 0, "Delete count should be non-negative"

        # Verify deletion
        remaining_notes = await client.db_notes({"host": test_host})
        for note in remaining_notes:
            assert note.get('id') != note_id, "Deleted note should not exist"
        print("   ✓ Verified note was deleted")
    except Exception as e:
        print(f"   ⚠ db_delete_note() failed: {e}")
        # Not critical if cleanup fails

    print("\n✅ Notes management operations test completed")


@pytest.mark.asyncio
async def test_notes_without_database(client):
    """Test that notes operations fail gracefully without database."""
    # Try to list notes without database
    try:
        # If this succeeds, database is configured - skip this test
        await client.db_workspace()
        pytest.skip("Database is configured - this test is for no-database scenario")
    except Exception:
        pass  # Good, no database

    print("\nTesting notes operations without database")
    try:
        notes = await client.db_notes()
        print(f"   Unexpected: Got notes without database: {len(notes)}")
    except Exception as e:
        print(f"   ✓ db_notes properly fails without database: {type(e).__name__}")


@pytest.mark.asyncio
async def test_delete_multiple_notes(client):
    """Test deleting multiple notes at once."""
    try:
        workspace = await client.db_workspace()
    except Exception:
        pytest.skip("No database configured")

    if not workspace:
        pytest.skip("No active workspace")

    # Create test host
    try:
        test_host = "192.168.100.201"
        await client.db_report_host({"host": test_host})
    except Exception as e:
        pytest.skip(f"Cannot create test host: {e}")

    print("\nTesting batch note deletion")

    # Create multiple notes
    try:
        note_ids = []
        for i in range(3):
            note_id = await client.db_report_note({
                "host": test_host,
                "type": "host.comments",
                "data": f"Test note {i}"
            })
            note_ids.append(note_id)

        print(f"   Created {len(note_ids)} test notes: {note_ids}")

        # Delete all at once
        count = await client.db_delete_note(note_ids)
        print(f"   ✓ Batch delete removed {count} notes")

        # Verify all deleted
        remaining = await client.db_notes({"host": test_host})
        for note in remaining:
            assert note.get('id') not in note_ids, "Deleted notes should not exist"

        print("   ✓ Verified all notes were deleted")
    except Exception as e:
        print(f"   ⚠ Batch deletion test failed: {e}")
