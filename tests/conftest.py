"""Pytest fixtures and configuration."""

import asyncio
import subprocess
import time
from pathlib import Path

import pytest

from assassinate.ipc import MsfClient


@pytest.fixture(scope="session")
def daemon_process():
    """Start daemon for testing session."""
    daemon_path = Path(__file__).parent.parent / "rust" / "daemon" / "target" / "release" / "daemon"
    msf_root = Path(__file__).parent.parent / "metasploit-framework"

    if not daemon_path.exists():
        pytest.skip("Daemon not built - run: cargo build --release -p daemon")

    # Kill any existing daemon
    subprocess.run(["pkill", "-f", "daemon.*msf-root"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    # Clean up shared memory
    subprocess.run(["rm", "-f", "/dev/shm/assassinate_msf_ipc*"], stderr=subprocess.DEVNULL)

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
    )

    # Wait for daemon to start
    time.sleep(5)

    # Verify it's running
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        pytest.fail(f"Daemon failed to start:\n{stderr.decode()}")

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
    module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
    yield module_id
    # Cleanup module to prevent memory leak
    await client.delete_module(module_id)
