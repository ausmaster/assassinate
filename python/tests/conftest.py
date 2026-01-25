"""Pytest fixtures and configuration for MSF tests.

This module provides fixtures for testing the direct Pyo3 bridge API.
The API is synchronous and does not require a daemon process.
"""

import os
import time

import pytest

import msf


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
    config.addinivalue_line(
        "markers",
        "db: marks tests that require database connection",
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


def get_target_smb_port() -> int:
    """Get the target SMB port (default: 445)."""
    return int(os.environ.get("TARGET_SMB_PORT", "445"))


def get_target_ftp_port() -> int:
    """Get the target FTP port (default: 21)."""
    return int(os.environ.get("TARGET_FTP_PORT", "21"))


def get_msf_root() -> str:
    """Get MSF installation path."""
    path = os.environ.get("MSF_ROOT", "~/Projects/metasploit-framework")
    return os.path.expanduser(path)


# =============================================================================
# Core Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def msf_init():
    """Initialize MSF framework once for all tests.

    This is a session-scoped fixture that initializes the embedded Ruby VM
    and loads the Metasploit framework. It only runs once per test session.
    """
    msf_root = get_msf_root()
    if not os.path.exists(msf_root):
        pytest.skip(f"MSF not found at {msf_root}. Set MSF_ROOT env var.")

    if not msf.is_initialized():
        msf.init_msf(msf_root)

    yield

    # No cleanup needed - framework stays loaded for session duration


@pytest.fixture
def exploit_module(msf_init):
    """Create a test exploit module (SambaCry)."""
    module = msf.create_module("exploit/linux/samba/is_known_pipename")
    yield module


@pytest.fixture
def auxiliary_module(msf_init):
    """Create a test auxiliary module (SMB version scanner)."""
    module = msf.create_module("auxiliary/scanner/smb/smb_version")
    yield module


@pytest.fixture
def post_module(msf_init):
    """Create a test post module."""
    module = msf.create_module("post/multi/gather/env")
    yield module


@pytest.fixture
def payload_module(msf_init):
    """Create a test payload module."""
    module = msf.create_module("payload/cmd/unix/reverse_bash")
    yield module


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
        "smb_port": get_target_smb_port(),
        "ftp_port": get_target_ftp_port(),
    }


@pytest.fixture
def shell_session(msf_init, integration_env):
    """Exploit SambaCry and return a shell session.

    This fixture:
    1. Creates the SambaCry exploit module
    2. Configures it for the target container
    3. Runs the exploit with cmd/unix/interact payload
    4. Yields the Session object
    5. Cleans up the session after test

    Requires: INTEGRATION_TESTS=true, target-linux container running
    """
    target_host = integration_env["target_host"]

    print(f"\n[*] Exploiting SambaCry on {target_host}")

    # Create and configure exploit
    exploit = msf.create_module("exploit/linux/samba/is_known_pipename")
    exploit.options.RHOSTS = target_host
    exploit.options.SMB_SHARE_NAME = "myshare"

    # Run exploit
    session = exploit.exploit("cmd/unix/interact", timeout=60)

    if session is None:
        pytest.fail("Failed to get shell session from exploit")

    print(f"[+] Got shell session: {session.sid}")

    yield session

    # Cleanup
    try:
        session.kill()
        print(f"[*] Cleaned up session {session.sid}")
    except Exception:
        pass


@pytest.fixture
def configured_exploit(msf_init, integration_env):
    """Return a SambaCry exploit configured for the target but not yet executed.

    Useful for tests that want to test validation, check(), etc. before exploiting.
    """
    target_host = integration_env["target_host"]

    exploit = msf.create_module("exploit/linux/samba/is_known_pipename")
    exploit.options.RHOSTS = target_host
    exploit.options.SMB_SHARE_NAME = "myshare"

    return exploit
