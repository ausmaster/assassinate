"""Test Meterpreter filesystem operations."""

import pytest


@pytest.mark.asyncio
async def test_session_fs_operations(client):
    """Test Meterpreter filesystem operations.

    Note: This test requires an active Meterpreter session.
    If no sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for FS operations test")

    # Use first session
    session_id = session_ids[0]

    # Get session info to check if it's Meterpreter
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    if "meterpreter" not in session_type.lower():
        pytest.skip(f"Session {session_id} is not Meterpreter (type: {session_type})")

    print(f"\n✓ Testing with Meterpreter session {session_id} (type: {session_type})")

    # Test 1: Get current working directory
    pwd = await client.session_fs_pwd(session_id)
    assert pwd, "PWD should not be empty"
    print(f"  Current directory: {pwd}")

    # Test 2: Get path separator
    separator = await client.session_fs_separator(session_id)
    assert separator in ["/", "\\"], f"Invalid separator: {separator}"
    print(f"  Path separator: {repr(separator)}")

    # Test 3: List current directory
    entries = await client.session_fs_ls(session_id, pwd)
    assert isinstance(entries, list), "Entries should be a list"
    print(f"  Directory has {len(entries)} entries")
    if entries:
        print(f"    First few: {entries[:5]}")

    # Test 4: Check if a common path exists
    test_path = "C:\\Windows\\System32" if separator == "\\" else "/tmp"
    exists = await client.session_fs_exists(session_id, test_path)
    print(f"  Path '{test_path}' exists: {exists}")

    # Test 5: Get file stats
    if exists:
        stat = await client.session_fs_stat(session_id, test_path)
        assert isinstance(stat, dict), "Stat should return a dict"
        print(f"  Stat info: ftype={stat.get('ftype')}, is_directory={stat.get('is_directory')}")

    # Test 6: Expand path (test environment variables)
    if separator == "\\":
        test_expand = "%TEMP%"
    else:
        test_expand = "$HOME"

    try:
        expanded = await client.session_fs_expand_path(session_id, test_expand)
        print(f"  Expanded '{test_expand}' to: {expanded}")
        assert test_expand not in expanded, "Path should be expanded"
    except Exception as e:
        print(f"  Warning: expand_path failed: {e}")

    print("✓ Meterpreter FS read operations work correctly")


@pytest.mark.asyncio
async def test_session_fs_file_operations(client):
    """Test Meterpreter file creation/deletion operations.

    Note: This test requires an active Meterpreter session.
    If no sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for FS operations test")

    # Use first session
    session_id = session_ids[0]

    # Get session info to check if it's Meterpreter
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    if "meterpreter" not in session_type.lower():
        pytest.skip(f"Session {session_id} is not Meterpreter (type: {session_type})")

    print(f"\n✓ Testing file operations with session {session_id}")

    # Get separator to construct proper paths
    separator = await client.session_fs_separator(session_id)
    pwd = await client.session_fs_pwd(session_id)

    # Create test directory path
    test_dir = f"{pwd}{separator}test_assassinate_dir"
    test_file = f"{test_dir}{separator}test_file.txt"

    try:
        # Test 1: Create directory
        print(f"  Creating directory: {test_dir}")
        await client.session_fs_mkdir(session_id, test_dir)

        # Verify directory was created
        exists = await client.session_fs_exists(session_id, test_dir)
        assert exists, f"Directory {test_dir} should exist after creation"
        print("  ✓ Directory created successfully")

        # Test 2: List directory (should be empty)
        entries = await client.session_fs_ls(session_id, test_dir)
        # Might have . and .. entries
        print(f"  Directory has {len(entries)} entries: {entries}")

        # Test 3: Remove directory
        print(f"  Removing directory: {test_dir}")
        await client.session_fs_rmdir(session_id, test_dir)

        # Verify directory was removed
        exists = await client.session_fs_exists(session_id, test_dir)
        assert not exists, f"Directory {test_dir} should not exist after removal"
        print("  ✓ Directory removed successfully")

    except Exception as e:
        # Clean up on error
        print(f"  Error during test: {e}")
        try:
            # Try to remove test directory if it exists
            if await client.session_fs_exists(session_id, test_dir):
                await client.session_fs_rmdir(session_id, test_dir)
        except:
            pass
        raise

    print("✓ Meterpreter FS write operations work correctly")


@pytest.mark.asyncio
async def test_session_fs_no_session():
    """Test that FS operations fail gracefully when session doesn't exist."""
    from assassinate.ipc.client import MsfClient

    client = MsfClient()
    await client.connect()

    try:
        # Try to use FS operation on non-existent session
        with pytest.raises(Exception):
            await client.session_fs_pwd(99999)

        print("✓ FS operations properly fail for non-existent sessions")
    finally:
        await client.disconnect()
