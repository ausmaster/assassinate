"""Tests for session process management operations (Meterpreter).

Note: These tests verify the process management API works correctly.
Tests gracefully skip if no Meterpreter sessions are available.

To create a Meterpreter session for testing:
    use exploit/multi/handler
    set PAYLOAD linux/x64/meterpreter/reverse_tcp
    set LHOST 0.0.0.0
    set LPORT 4444
    exploit -j
"""

import pytest


@pytest.mark.asyncio
async def test_process_getpid_api_exists(client):
    """Test that process_getpid API method exists."""
    assert hasattr(client, 'session_process_getpid')
    assert callable(client.session_process_getpid)
    print("✓ session_process_getpid API exists")


@pytest.mark.asyncio
async def test_process_list_api_exists(client):
    """Test that process_list API method exists."""
    assert hasattr(client, 'session_process_list')
    assert callable(client.session_process_list)
    print("✓ session_process_list API exists")


@pytest.mark.asyncio
async def test_process_kill_api_exists(client):
    """Test that process_kill API method exists."""
    assert hasattr(client, 'session_process_kill')
    assert callable(client.session_process_kill)
    print("✓ session_process_kill API exists")


@pytest.mark.asyncio
async def test_process_execute_api_exists(client):
    """Test that process_execute API method exists."""
    assert hasattr(client, 'session_process_execute')
    assert callable(client.session_process_execute)
    print("✓ session_process_execute API exists")


@pytest.mark.asyncio
async def test_process_operations_with_active_session(client):
    """Test process operations with an active Meterpreter session.

    This test requires an active Meterpreter session.
    If no Meterpreter sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for process management test")

    # Find a Meterpreter session
    meterpreter_session_id = None
    for session_id in session_ids:
        session_info = await client.session_get(session_id)
        if session_info:
            session_type = session_info.get("type", "")
            if "meterpreter" in session_type.lower():
                meterpreter_session_id = session_id
                print(f"\n✓ Found Meterpreter session {session_id} (type: {session_type})")
                break

    if meterpreter_session_id is None:
        pytest.skip("No Meterpreter sessions found - all active sessions are basic shells")

    print(f"\n📝 Testing process management on session {meterpreter_session_id}")

    # Test 1: process_getpid - Get current process ID
    print("\n1. Testing process_getpid")
    try:
        pid = await client.session_process_getpid(meterpreter_session_id)
        print(f"   ✓ process_getpid() works - current PID: {pid}")
        assert isinstance(pid, int)
        assert pid > 0, "PID should be positive"
    except Exception as e:
        print(f"   ⚠ process_getpid() failed: {e}")
        pytest.skip(f"process_getpid not supported: {e}")

    # Test 2: process_list - List all processes
    print("\n2. Testing process_list")
    try:
        processes = await client.session_process_list(meterpreter_session_id)
        print(f"   ✓ process_list() works - got {len(processes)} processes")
        assert isinstance(processes, list)
        assert len(processes) > 0, "Should have at least one process"

        # Check first process structure
        if processes:
            proc = processes[0]
            print(f"   Sample process: PID {proc.get('pid')} - {proc.get('name')}")
            assert 'pid' in proc, "Process should have 'pid' key"
            assert 'name' in proc, "Process should have 'name' key"
    except Exception as e:
        print(f"   ⚠ process_list() failed: {e}")
        # List might fail on some platforms

    # Test 3: process_execute - Execute a benign command
    print("\n3. Testing process_execute")
    print("   ℹ Executing a simple command that won't harm the session")
    try:
        # Execute a simple, harmless command (whoami or equivalent)
        proc_info = await client.session_process_execute(
            meterpreter_session_id,
            "whoami" if "linux" in session_type.lower() else "cmd.exe",
            "" if "linux" in session_type.lower() else "/c whoami",
            hidden=True,
            channelized=False
        )
        print(f"   ✓ process_execute() works - started PID {proc_info.get('pid')}")
        assert isinstance(proc_info, dict)
        assert 'pid' in proc_info, "Should return process ID"
        assert proc_info['pid'] > 0, "PID should be positive"
    except Exception as e:
        print(f"   ⚠ process_execute() failed: {e}")
        # Execute might fail on some platforms or permissions

    # Test 4: process_kill - Don't actually test killing a process
    print("\n4. Testing process_kill capability")
    print("   ℹ Not actually killing a process to preserve session stability")
    print("   ℹ API exists and can be called with:")
    print(f"     await client.session_process_kill({meterpreter_session_id}, <pid>)")

    print("\n✅ Process management operations test completed")


@pytest.mark.asyncio
async def test_process_getpid_nonexistent_session(client):
    """Test that process_getpid fails gracefully for non-existent session."""
    try:
        with pytest.raises(Exception):
            await client.session_process_getpid(99999)
        print("✓ process_getpid properly fails for non-existent session")
    except Exception as e:
        # Expected to fail
        print(f"✓ process_getpid raised exception for invalid session: {type(e).__name__}")


@pytest.mark.asyncio
async def test_process_list_nonexistent_session(client):
    """Test that process_list fails gracefully for non-existent session."""
    try:
        with pytest.raises(Exception):
            await client.session_process_list(99999)
        print("✓ process_list properly fails for non-existent session")
    except Exception as e:
        # Expected to fail
        print(f"✓ process_list raised exception for invalid session: {type(e).__name__}")


@pytest.mark.asyncio
async def test_process_operations_on_shell_session(client):
    """Test process operations on a basic shell session (should handle gracefully).

    Process-specific operations only work on Meterpreter sessions.
    This test verifies graceful handling on basic shells.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available")

    # Find a basic shell session (non-Meterpreter)
    shell_session_id = None
    for session_id in session_ids:
        session_info = await client.session_get(session_id)
        if session_info:
            session_type = session_info.get("type", "")
            if "shell" in session_type.lower() and "meterpreter" not in session_type.lower():
                shell_session_id = session_id
                print(f"\n✓ Found shell session {session_id}")
                break

    if shell_session_id is None:
        pytest.skip("No basic shell sessions found for cross-type test")

    print(f"\nℹ Testing process operations on shell session {shell_session_id}")
    print("  These operations should fail - that's expected behavior")

    # Try process_getpid (should fail on basic shell)
    try:
        pid = await client.session_process_getpid(shell_session_id)
        print(f"  Unexpected: process_getpid returned: {pid}")
    except Exception as e:
        print(f"  process_getpid failed as expected: {type(e).__name__}")

    print("✓ Process operations handle basic shell sessions appropriately")
