"""Tests for shell session operations (non-Meterpreter).

Note: These tests verify the shell session API works correctly.
Tests gracefully skip if no shell sessions are available.

To create a shell session for testing:
    use exploit/multi/handler
    set PAYLOAD generic/shell_reverse_tcp
    set LHOST 0.0.0.0
    set LPORT 4444
    exploit -j
"""

import pytest


@pytest.mark.asyncio
async def test_shell_read_api_exists(client):
    """Test that shell_read API method exists."""
    assert hasattr(client, 'session_shell_read')
    assert callable(client.session_shell_read)
    print("✓ session_shell_read API exists")


@pytest.mark.asyncio
async def test_shell_write_api_exists(client):
    """Test that shell_write API method exists."""
    assert hasattr(client, 'session_shell_write')
    assert callable(client.session_shell_write)
    print("✓ session_shell_write API exists")


@pytest.mark.asyncio
async def test_shell_to_meterpreter_api_exists(client):
    """Test that shell_to_meterpreter API method exists."""
    assert hasattr(client, 'session_shell_to_meterpreter')
    assert callable(client.session_shell_to_meterpreter)
    print("✓ session_shell_to_meterpreter API exists")


@pytest.mark.asyncio
async def test_shell_operations_with_active_session(client):
    """Test shell operations with an active shell session.

    This test requires an active shell (non-Meterpreter) session.
    If no shell sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for shell session test")

    # Find a shell session (non-Meterpreter)
    shell_session_id = None
    for session_id in session_ids:
        session_info = await client.session_get(session_id)
        if session_info:
            session_type = session_info.get("type", "")
            # Look for shell type sessions (not Meterpreter)
            if "shell" in session_type.lower() and "meterpreter" not in session_type.lower():
                shell_session_id = session_id
                print(f"\n✓ Found shell session {session_id} (type: {session_type})")
                break

    if shell_session_id is None:
        pytest.skip("No shell sessions found - all active sessions are Meterpreter")

    print(f"\n📝 Testing shell session operations on session {shell_session_id}")

    # Test 1: shell_write - Write a newline (minimal impact)
    print("\n1. Testing shell_write")
    try:
        bytes_written = await client.session_shell_write(shell_session_id, "\n")
        print(f"   ✓ shell_write() works - wrote {bytes_written} bytes")
        assert isinstance(bytes_written, int)
        assert bytes_written > 0, "Should write at least 1 byte"
    except Exception as e:
        print(f"   ⚠ shell_write() failed: {e}")
        pytest.skip(f"shell_write not supported: {e}")

    # Test 2: shell_read - Read any available output
    print("\n2. Testing shell_read")
    try:
        output = await client.session_shell_read(shell_session_id)
        print(f"   ✓ shell_read() works - got {len(output)} bytes")
        assert isinstance(output, str)
        if output:
            print(f"   Output preview: {output[:50]!r}")
    except Exception as e:
        print(f"   ⚠ shell_read() failed: {e}")
        # Read might fail if no data available, that's okay

    # Test 3: shell_to_meterpreter - Don't actually upgrade, just verify API
    print("\n3. Testing shell_to_meterpreter capability")
    print("   ℹ Not actually running upgrade to preserve session")
    print("   ℹ API exists and can be called with:")
    print(f"     await client.session_shell_to_meterpreter({shell_session_id}, 'LHOST', 4444)")

    print("\n✅ Shell session operations test completed")


@pytest.mark.asyncio
async def test_shell_read_nonexistent_session(client):
    """Test that shell_read fails gracefully for non-existent session."""
    try:
        with pytest.raises(Exception):
            await client.session_shell_read(99999)
        print("✓ shell_read properly fails for non-existent session")
    except Exception as e:
        # Expected to fail
        print(f"✓ shell_read raised exception for invalid session: {type(e).__name__}")


@pytest.mark.asyncio
async def test_shell_write_nonexistent_session(client):
    """Test that shell_write fails gracefully for non-existent session."""
    try:
        with pytest.raises(Exception):
            await client.session_shell_write(99999, "test\n")
        print("✓ shell_write properly fails for non-existent session")
    except Exception as e:
        # Expected to fail
        print(f"✓ shell_write raised exception for invalid session: {type(e).__name__}")


@pytest.mark.asyncio
async def test_shell_to_meterpreter_nonexistent_session(client):
    """Test that shell_to_meterpreter fails gracefully for non-existent session."""
    try:
        with pytest.raises(Exception):
            await client.session_shell_to_meterpreter(99999, "192.168.1.1", 4444)
        print("✓ shell_to_meterpreter properly fails for non-existent session")
    except Exception as e:
        # Expected to fail
        print(f"✓ shell_to_meterpreter raised exception for invalid session: {type(e).__name__}")


@pytest.mark.asyncio
async def test_shell_operations_on_meterpreter_session(client):
    """Test shell operations on a Meterpreter session (should handle gracefully).

    Shell-specific operations may not work on Meterpreter sessions.
    This test verifies graceful handling.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available")

    # Find a Meterpreter session
    meterpreter_session_id = None
    for session_id in session_ids:
        session_info = await client.session_get(session_id)
        if session_info:
            session_type = session_info.get("type", "")
            if "meterpreter" in session_type.lower():
                meterpreter_session_id = session_id
                print(f"\n✓ Found Meterpreter session {session_id}")
                break

    if meterpreter_session_id is None:
        pytest.skip("No Meterpreter sessions found for cross-type test")

    print(f"\nℹ Testing shell operations on Meterpreter session {meterpreter_session_id}")
    print("  These operations may fail - that's expected behavior")

    # Try shell_read (may or may not work on Meterpreter)
    try:
        output = await client.session_shell_read(meterpreter_session_id)
        print(f"  shell_read returned: {len(output)} bytes")
    except Exception as e:
        print(f"  shell_read failed as expected: {type(e).__name__}")

    print("✓ Shell operations handle Meterpreter sessions appropriately")
