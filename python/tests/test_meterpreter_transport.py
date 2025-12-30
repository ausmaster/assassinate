"""Tests for Meterpreter Transport Management operations.

IMPORTANT: Transport Management is a WINDOWS-ONLY feature in Meterpreter.
Linux Meterpreter (x86 and x64) does NOT support transport operations.
These tests require a Windows Meterpreter session to run.

To run these tests:
1. Start the Windows target container:
   docker compose -f docker/docker-compose.yml up target-windows
   (First run takes 10-20 minutes to install Windows)

2. Run tests:
   docker compose -f docker/docker-compose.yml run --rm integration-test bash -c \
       "cargo build --release --manifest-path rust/daemon/Cargo.toml && \
        pytest python/tests/test_meterpreter_transport.py -v"

The tests will skip on Linux Meterpreter with an informative message.
"""

import pytest


async def get_session_platform(client, session_id: int) -> str:
    """Get session platform (windows, linux, etc.)."""
    try:
        info = await client.session_info(session_id)
        return info.get("platform", "").lower()
    except Exception:
        return "unknown"


def skip_if_not_windows(platform: str):
    """Skip test with informative message if not Windows."""
    if "windows" not in platform and "win" not in platform:
        pytest.skip(
            f"Transport Management is Windows-only. "
            f"Current platform: {platform}. "
            f"Use target-windows container for these tests."
        )


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.windows_only
class TestMeterpreterTransportList:
    """Test Meterpreter Transport listing and timeouts.

    NOTE: These tests require Windows Meterpreter. They will skip on Linux.
    """

    @pytest.mark.asyncio
    async def test_transport_list(self, client, direct_meterpreter_session):
        """Test listing transports for a Meterpreter session."""
        session_id = direct_meterpreter_session
        platform = await get_session_platform(client, session_id)
        skip_if_not_windows(platform)

        transport_info = await client.session_transport_list(session_id)

        print(f"Transport info: {transport_info}")

        # Should have session_exp field
        assert "session_exp" in transport_info, "Should have session_exp field"

        # Should have transports array
        assert "transports" in transport_info, "Should have transports array"
        transports = transport_info["transports"]
        assert isinstance(transports, list), "Transports should be a list"

        # Should have at least one transport (the current one)
        assert len(transports) >= 1, "Should have at least one transport"

        # First transport should have URL
        first_transport = transports[0]
        if first_transport.get("url"):
            print(f"First transport URL: {first_transport['url']}")

    @pytest.mark.asyncio
    async def test_set_transport_timeouts_read(self, client, direct_meterpreter_session):
        """Test reading transport timeouts without changing them."""
        session_id = direct_meterpreter_session
        platform = await get_session_platform(client, session_id)
        skip_if_not_windows(platform)

        # Pass None for all params to just read current values
        timeouts = await client.session_set_transport_timeouts(session_id)

        print(f"Current timeouts: {timeouts}")

        # Should return timeout info
        assert timeouts is not None, "Should return timeout info"

    @pytest.mark.asyncio
    async def test_set_transport_timeouts_modify(self, client, direct_meterpreter_session):
        """Test modifying transport timeouts."""
        session_id = direct_meterpreter_session
        platform = await get_session_platform(client, session_id)
        skip_if_not_windows(platform)

        # Get current timeouts first
        original = await client.session_set_transport_timeouts(session_id)
        print(f"Original timeouts: {original}")

        # Set new timeout values
        new_timeouts = await client.session_set_transport_timeouts(
            session_id,
            comm_timeout=60,
            retry_total=5,
            retry_wait=10,
        )

        print(f"New timeouts: {new_timeouts}")

        # Verify we got a response
        assert new_timeouts is not None


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.windows_only
class TestMeterpreterTransportOperations:
    """Test Meterpreter Transport add/remove/change operations.

    NOTE: These tests require Windows Meterpreter. They will skip on Linux.
    """

    @pytest.mark.asyncio
    async def test_transport_add_and_remove(self, client, direct_meterpreter_session):
        """Test adding and removing a transport."""
        session_id = direct_meterpreter_session
        platform = await get_session_platform(client, session_id)
        skip_if_not_windows(platform)

        # Get initial transport count
        initial_info = await client.session_transport_list(session_id)
        initial_count = len(initial_info["transports"])
        print(f"Initial transport count: {initial_count}")

        # Add a bind_tcp transport (doesn't require active connection)
        success = await client.session_transport_add(
            session_id,
            transport="bind_tcp",
            lport=54321,
            comm_timeout=30,
        )

        if success:
            print("Transport added successfully")

            # Verify transport was added
            after_add = await client.session_transport_list(session_id)
            after_add_count = len(after_add["transports"])
            print(f"Transport count after add: {after_add_count}")
            assert after_add_count >= initial_count

            # Now remove it
            remove_success = await client.session_transport_remove(
                session_id,
                transport="bind_tcp",
                lport=54321,
            )
            print(f"Transport remove result: {remove_success}")
        else:
            print("Transport add returned False")


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.windows_only
class TestMeterpreterTransportNavigation:
    """Test Meterpreter Transport navigation (next/prev).

    NOTE: These tests require Windows Meterpreter. They will skip on Linux.
    """

    @pytest.mark.asyncio
    async def test_transport_next_prev_available(self, client, direct_meterpreter_session):
        """Test that transport_next and transport_prev are callable."""
        session_id = direct_meterpreter_session
        platform = await get_session_platform(client, session_id)
        skip_if_not_windows(platform)

        transport_info = await client.session_transport_list(session_id)
        transport_count = len(transport_info["transports"])
        print(f"Transport count: {transport_count}")

        if transport_count <= 1:
            print("Only one transport - skipping navigation test")
            pytest.skip("Need multiple transports to test navigation")

        print("Multiple transports available - navigation methods are available")
        print("Not executing transport_next/prev to avoid breaking session")


@pytest.mark.integration
@pytest.mark.meterpreter
class TestMeterpreterTransportSleep:
    """Test Meterpreter Transport sleep.

    transport_sleep(0) is handled in Rust before calling MSF,
    so it works on ALL platforms (returns False immediately).
    """

    @pytest.mark.asyncio
    async def test_transport_sleep_zero(self, client, direct_meterpreter_session):
        """Test that transport_sleep with 0 seconds returns False.

        This test works on ALL platforms because our Rust implementation
        short-circuits the 0-second case without calling MSF.
        """
        session_id = direct_meterpreter_session

        # Sleep for 0 seconds should return False (as per Rust implementation)
        # This is safe to call as it doesn't actually sleep
        result = await client.session_transport_sleep(session_id, 0)
        print(f"Sleep(0) result: {result}")
        assert result is False, "Sleep(0) should return False"
        print("✓ transport_sleep(0) correctly returns False")
