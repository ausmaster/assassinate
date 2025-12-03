"""Pytest fixtures and configuration."""

import os
import subprocess
import time
from pathlib import Path

import pytest

from assassinate.ipc import MsfClient


@pytest.fixture(scope="session")
def daemon_process():
    """Start daemon for testing session."""
    # Check CARGO_TARGET_DIR first (used in CI containers), then fall back to default
    cargo_target_dir = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target_dir:
        daemon_path = Path(cargo_target_dir) / "release" / "daemon"
    else:
        daemon_path = (
            Path(__file__).parent.parent
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
        msf_root = Path(__file__).parent.parent / "metasploit-framework"

    if not daemon_path.exists():
        pytest.skip("Daemon not built - run: cargo build --release -p daemon")

    # Kill any existing daemon
    subprocess.run(
        ["pkill", "-f", "daemon.*msf-root"], stderr=subprocess.DEVNULL
    )
    time.sleep(1)

    # Clean up shared memory
    subprocess.run(
        ["rm", "-f", "/dev/shm/assassinate_msf_ipc*"], stderr=subprocess.DEVNULL
    )

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

    # Start daemon
    proc = subprocess.Popen(
        [
            str(daemon_path),
            "--msf-root",
            str(msf_root),
            "--log-level",
            "info",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    # Wait for daemon to start and initialize
    time.sleep(8)

    # Verify it's running
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        print(f"\n=== DAEMON STARTUP FAILED ===")
        print(f"Command: {daemon_path} --msf-root {msf_root}")
        print(f"STDERR:\n{stderr.decode()}")
        print(f"STDOUT:\n{stdout.decode()}")
        print(f"LD_LIBRARY_PATH: {env.get('LD_LIBRARY_PATH')}")
        print(f"ASSASSINATE_WORKSPACE: {env.get('ASSASSINATE_WORKSPACE')}")
        pytest.fail(f"Daemon failed to start:\n{stderr.decode()}")

    # Double-check shared memory was created
    import glob

    shm_files = glob.glob("/dev/shm/assassinate_msf_ipc*")
    if not shm_files:
        # Wait a bit more for slow initialization
        time.sleep(5)
        shm_files = glob.glob("/dev/shm/assassinate_msf_ipc*")
        if not shm_files:
            stdout, stderr = (
                proc.communicate() if proc.poll() is not None else (b"", b"")
            )
            pytest.fail(
                f"Daemon started but shared memory not created. Daemon may have crashed.\nSTDERR: {stderr.decode()}\nSTDOUT: {stdout.decode()}"
            )

    yield proc

    # Cleanup
    proc.terminate()
    proc.wait(timeout=5)


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
