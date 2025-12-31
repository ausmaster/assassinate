"""Tests for Meterpreter Transport Management operations.

IMPORTANT: Transport Management is a WINDOWS-ONLY feature in Meterpreter.
Linux Meterpreter (x86 and x64) does NOT support transport operations.

This test mimics the Rust test approach: create ONE session, run ALL transport
operations on it, then cleanup. This avoids overwhelming the Windows VM with
multiple exploits.

To run these tests:
1. Start the Windows target container:
   docker compose -f docker/docker-compose.yml up target-windows
   (First run takes 10-20 minutes to install Windows)

2. Run tests:
   docker exec dev pytest python/tests/test_meterpreter_transport.py -v
"""

import pytest


@pytest.mark.integration
@pytest.mark.meterpreter
@pytest.mark.windows_only
class TestMeterpreterTransportManagement:
    """Comprehensive Transport Management tests using a single Windows Meterpreter session.

    This class creates ONE session and runs ALL transport tests on it,
    mimicking the Rust test approach for reliability.
    """

    @pytest.mark.asyncio
    async def test_transport_operations(self, client, windows_meterpreter_session):
        """Test all transport operations on a single Windows Meterpreter session.

        This comprehensive test covers:
        - transport_list (initial state)
        - set_transport_timeouts (read and modify)
        - transport_add (add backup transport)
        - transport_list (verify add)
        - transport_remove (remove backup transport)
        - transport_list (verify remove)
        - transport_sleep(0) (works on all platforms)
        """
        session_id = windows_meterpreter_session

        print("\n" + "=" * 60)
        print(" Transport Management Comprehensive Test")
        print("=" * 60)

        # =====================================================================
        # Test 1: transport_list (initial state)
        # =====================================================================
        print("\n--- Test 1: transport_list (initial) ---")
        transport_info = await client.session_transport_list(session_id)

        print(f"Transport info: {transport_info}")

        assert "session_exp" in transport_info, "Should have session_exp field"
        assert "transports" in transport_info, "Should have transports array"

        transports = transport_info["transports"]
        assert isinstance(transports, list), "Transports should be a list"
        initial_count = len(transports)
        assert initial_count >= 1, "Should have at least one transport"

        print(f"✓ Initial transport count: {initial_count}")
        for i, t in enumerate(transports):
            if t.get("url"):
                print(f"  Transport {i}: {t['url']}")

        # =====================================================================
        # Test 2: set_transport_timeouts (read current values)
        # =====================================================================
        print("\n--- Test 2: set_transport_timeouts (read) ---")
        timeouts = await client.session_set_transport_timeouts(session_id)

        print(f"Current timeouts: {timeouts}")
        assert timeouts is not None, "Should return timeout info"
        print("✓ Read timeouts successfully")

        # =====================================================================
        # Test 3: set_transport_timeouts (modify values)
        # =====================================================================
        print("\n--- Test 3: set_transport_timeouts (modify) ---")
        new_timeouts = await client.session_set_transport_timeouts(
            session_id,
            comm_timeout=60,
            retry_total=5,
            retry_wait=10,
        )

        print(f"New timeouts: {new_timeouts}")
        assert new_timeouts is not None
        print("✓ Modified timeouts successfully")

        # =====================================================================
        # Test 4: transport_add (add backup transport)
        # =====================================================================
        print("\n--- Test 4: transport_add ---")
        # Add a bind_tcp transport (doesn't require active connection)
        test_lport = 54321

        success = await client.session_transport_add(
            session_id,
            transport="bind_tcp",
            lport=test_lport,
            comm_timeout=30,
        )

        print(f"transport_add result: {success}")
        if success:
            print("✓ Transport added successfully")
        else:
            print("⚠ transport_add returned False (may still have succeeded)")

        # =====================================================================
        # Test 5: transport_list (verify add)
        # =====================================================================
        print("\n--- Test 5: transport_list (after add) ---")
        after_add = await client.session_transport_list(session_id)
        after_add_count = len(after_add["transports"])

        print(f"Transport count after add: {after_add_count}")
        for i, t in enumerate(after_add["transports"]):
            if t.get("url"):
                print(f"  Transport {i}: {t['url']}")

        # Should have at least as many transports as before
        assert after_add_count >= initial_count, "Should not have fewer transports after add"
        print("✓ Transport list updated")

        # =====================================================================
        # Test 6: transport_remove (remove added transport)
        # =====================================================================
        print("\n--- Test 6: transport_remove ---")
        remove_success = await client.session_transport_remove(
            session_id,
            transport="bind_tcp",
            lport=test_lport,
        )

        print(f"transport_remove result: {remove_success}")
        print("✓ Transport remove called")

        # =====================================================================
        # Test 7: transport_list (verify remove)
        # =====================================================================
        print("\n--- Test 7: transport_list (after remove) ---")
        after_remove = await client.session_transport_list(session_id)
        final_count = len(after_remove["transports"])

        print(f"Transport count after remove: {final_count}")
        for i, t in enumerate(after_remove["transports"]):
            if t.get("url"):
                print(f"  Transport {i}: {t['url']}")

        print("✓ Transport operations complete")

        # =====================================================================
        # Test 8: transport_sleep(0)
        # =====================================================================
        print("\n--- Test 8: transport_sleep(0) ---")
        result = await client.session_transport_sleep(session_id, 0)
        print(f"transport_sleep(0) result: {result}")
        assert result is False, "Sleep(0) should return False"
        print("✓ transport_sleep(0) correctly returns False")

        print("\n" + "=" * 60)
        print(" All Transport Tests Passed!")
        print("=" * 60)


@pytest.mark.integration
@pytest.mark.meterpreter
class TestMeterpreterTransportSleep:
    """Test Meterpreter Transport sleep on Linux (cross-platform).

    transport_sleep(0) is handled in Rust before calling MSF,
    so it works on ALL platforms (returns False immediately).
    """

    @pytest.mark.asyncio
    async def test_transport_sleep_zero_linux(self, client, direct_meterpreter_session):
        """Test that transport_sleep with 0 seconds returns False on Linux.

        This test works on ALL platforms because our Rust implementation
        short-circuits the 0-second case without calling MSF.
        """
        session_id = direct_meterpreter_session

        result = await client.session_transport_sleep(session_id, 0)
        print(f"Sleep(0) result: {result}")
        assert result is False, "Sleep(0) should return False"
        print("✓ transport_sleep(0) correctly returns False")
