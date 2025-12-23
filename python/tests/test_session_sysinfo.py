"""Test Meterpreter system information operations."""

import pytest


@pytest.mark.asyncio
async def test_session_system_info(client):
    """Test Meterpreter system information gathering.

    Note: This test requires an active Meterpreter session.
    If no sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for system info test")

    # Use first session
    session_id = session_ids[0]

    # Get session info to check if it's Meterpreter
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    if "meterpreter" not in session_type.lower():
        pytest.skip(f"Session {session_id} is not Meterpreter (type: {session_type})")

    print(f"\n✓ Testing with Meterpreter session {session_id} (type: {session_type})")

    # Test 1: Get system information
    sysinfo = await client.session_sys_sysinfo(session_id)
    assert isinstance(sysinfo, dict), "sysinfo should be a dict"
    assert "OS" in sysinfo, "sysinfo should contain 'OS'"
    print(f"  OS: {sysinfo.get('OS')}")
    print(f"  Architecture: {sysinfo.get('Architecture')}")
    print(f"  Computer: {sysinfo.get('Computer')}")
    if "Domain" in sysinfo and sysinfo["Domain"]:
        print(f"  Domain: {sysinfo['Domain']}")

    # Test 2: Get current user
    uid = await client.session_sys_getuid(session_id)
    assert uid, "UID should not be empty"
    print(f"  Running as: {uid}")

    # Test 3: Get local time on target
    localtime = await client.session_sys_localtime(session_id)
    assert localtime, "Local time should not be empty"
    print(f"  Target time: {localtime}")

    # Test 4: Get environment variable
    # Try to get PATH (cross-platform)
    path = await client.session_sys_getenv(session_id, "PATH")
    if path:
        print(f"  PATH: {path[:100]}...")  # Truncate for readability
        assert len(path) > 0, "PATH should not be empty"

    # Test 5: Get multiple environment variables
    var_names = ["PATH", "HOME", "USER", "USERPROFILE", "USERNAME"]
    envs = await client.session_sys_getenvs(session_id, var_names)
    assert isinstance(envs, dict), "envs should be a dict"
    print(f"  Retrieved {len(envs)} environment variables:")
    for name, value in list(envs.items())[:3]:
        print(f"    {name}: {value[:50]}...")

    # Test 6: Try Windows-specific operations (will fail gracefully on Linux)
    try:
        sid = await client.session_sys_getsid(session_id)
        if sid:
            print(f"  SID: {sid}")

            # Check if running as SYSTEM
            is_system = await client.session_sys_is_system(session_id)
            print(f"  Running as SYSTEM: {is_system}")
    except Exception as e:
        print(f"  Windows-specific operations not supported: {e}")

    # Test 7: Try to get privileges (Windows only)
    try:
        privs = await client.session_sys_getprivs(session_id)
        if privs:
            print(f"  Enabled privileges ({len(privs)} total):")
            for priv in privs[:5]:
                print(f"    - {priv}")
            if len(privs) > 5:
                print(f"    ... and {len(privs) - 5} more")
    except Exception as e:
        print(f"  Get privileges failed (expected on non-Windows): {e}")

    # Test 8: Try to get drivers (Windows only)
    try:
        drivers = await client.session_sys_getdrivers(session_id)
        if drivers:
            print(f"  Loaded drivers ({len(drivers)} total):")
            for driver in drivers[:3]:
                print(f"    - {driver.get('basename')}: {driver.get('filename')}")
            if len(drivers) > 3:
                print(f"    ... and {len(drivers) - 3} more")
    except Exception as e:
        print(f"  Get drivers failed (expected on non-Windows): {e}")

    print("✓ System information test completed successfully")
