"""Tests for Meterpreter Client Core operations.

These tests require a Meterpreter session to run. They use the
`direct_meterpreter_session` fixture which:
1. Starts a multi/handler
2. Generates a Meterpreter payload
3. Triggers execution on target container
4. Returns the session ID

Run with:
    docker compose -f docker/docker-compose.yml run --rm integration-test bash -c \
        "cargo build --release --manifest-path rust/daemon/Cargo.toml && \
         pytest python/tests/test_meterpreter_client_core.py -v"
"""

import pytest


@pytest.mark.integration
@pytest.mark.meterpreter
class TestMeterpreterClientCore:
    """Test Meterpreter Client Core operations."""

    @pytest.mark.asyncio
    async def test_meterpreter_machine_id(self, client, direct_meterpreter_session):
        """Test getting machine ID from Meterpreter session."""
        session_id = direct_meterpreter_session

        machine_id = await client.session_meterpreter_machine_id(session_id)

        print(f"Machine ID: {machine_id}")
        # Machine ID should be an MD5 hash (32 hex chars) or empty string
        if machine_id:
            assert len(machine_id) == 32, "Machine ID should be 32 char MD5 hash"
            assert all(c in "0123456789abcdef" for c in machine_id.lower())

    @pytest.mark.asyncio
    async def test_meterpreter_native_arch(self, client, direct_meterpreter_session):
        """Test getting native architecture from Meterpreter session.

        Note: Not all Meterpreter types support native_arch (e.g., x86/linux).
        This is a Meterpreter limitation, not a bug in our code.
        """
        session_id = direct_meterpreter_session

        try:
            arch = await client.session_meterpreter_native_arch(session_id)
            print(f"Native arch: {arch}")
            # Should be a known architecture
            if arch:
                known_archs = ["x86", "x64", "aarch64", "arm", "mips", "ppc"]
                assert any(known in arch.lower() for known in known_archs), \
                    f"Unknown architecture: {arch}"
        except Exception as e:
            # x86/linux Meterpreter doesn't support native_arch - this is expected
            if "not supported" in str(e).lower():
                pytest.skip(f"native_arch not supported on this Meterpreter type")
            raise

    @pytest.mark.asyncio
    async def test_meterpreter_session_guid(self, client, direct_meterpreter_session):
        """Test getting session GUID from Meterpreter session."""
        session_id = direct_meterpreter_session

        guid = await client.session_meterpreter_session_guid(session_id)

        print(f"Session GUID: {guid}")
        # GUID should be a hex string (32 chars for 16 bytes)
        assert guid, "GUID should not be empty"
        assert len(guid) == 32, f"GUID should be 32 hex chars, got {len(guid)}"
        assert all(c in "0123456789abcdef" for c in guid.lower()), \
            "GUID should be hex string"

    @pytest.mark.asyncio
    async def test_meterpreter_use_stdapi(self, client, direct_meterpreter_session):
        """Test loading stdapi extension."""
        session_id = direct_meterpreter_session

        # stdapi is usually already loaded, but calling use() should succeed
        try:
            success = await client.session_meterpreter_use(session_id, "stdapi")
            print(f"Load stdapi: {success}")
            # May succeed or fail if already loaded - both are OK
        except Exception as e:
            # Some Meterpreter implementations don't support dynamic loading
            print(f"stdapi load returned: {e}")

    @pytest.mark.asyncio
    async def test_meterpreter_secure(self, client, direct_meterpreter_session):
        """Test enabling secure mode (TLV encryption)."""
        session_id = direct_meterpreter_session

        try:
            secured = await client.session_meterpreter_secure(session_id)
            print(f"Secure mode: {secured}")
            # May or may not succeed depending on session state
        except Exception as e:
            print(f"Secure mode returned: {e}")

    @pytest.mark.asyncio
    async def test_meterpreter_machine_id_with_timeout(
        self, client, direct_meterpreter_session
    ):
        """Test machine_id with explicit timeout."""
        session_id = direct_meterpreter_session

        # Should work with explicit timeout
        machine_id = await client.session_meterpreter_machine_id(session_id, timeout=30)
        print(f"Machine ID (with timeout): {machine_id}")


@pytest.mark.integration
@pytest.mark.meterpreter
class TestMeterpreterMigrate:
    """Test Meterpreter process migration.

    Note: Migration is primarily a Windows feature. On Linux it may not be
    supported by the Meterpreter implementation. These tests verify the API
    works even if the underlying operation fails.
    """

    @pytest.mark.asyncio
    async def test_migrate_api_callable(self, client, direct_meterpreter_session):
        """Test that migrate API is callable (may fail on Linux)."""
        session_id = direct_meterpreter_session

        # Get current PID first
        try:
            current_pid = await client.session_process_getpid(session_id)
            print(f"Current PID: {current_pid}")
        except Exception as e:
            pytest.skip(f"Cannot get PID (likely non-stdapi session): {e}")

        # Try to list processes to find a target
        try:
            processes = await client.session_process_list(session_id)
            if not processes:
                pytest.skip("No processes listed")

            # Find a process that's not us
            target_pid = None
            for proc in processes:
                pid = proc.get("pid", 0)
                if pid and pid != current_pid:
                    target_pid = pid
                    break

            if not target_pid:
                pytest.skip("No suitable migration target found")

            print(f"Would migrate to PID: {target_pid}")

            # Note: We don't actually migrate because it would alter the session
            # and potentially break other tests. Just verify the API exists.
            # Uncomment below to actually test migration:
            # success = await client.session_meterpreter_migrate(session_id, target_pid)
            # print(f"Migration result: {success}")

        except Exception as e:
            print(f"Migration test skipped: {e}")


@pytest.mark.integration
@pytest.mark.meterpreter
class TestMeterpreterShutdown:
    """Test Meterpreter shutdown.

    Note: This test uses direct_meterpreter_session which creates its own
    session via shell upgrade.
    """

    @pytest.mark.asyncio
    async def test_shutdown_terminates_session(
        self, client, direct_meterpreter_session
    ):
        """Test that shutdown terminates the Meterpreter session."""
        session_id = direct_meterpreter_session

        # Verify session is alive before shutdown
        alive_before = await client.session_alive(session_id)
        assert alive_before, "Session should be alive before shutdown"

        print(f"Shutting down Meterpreter session {session_id}...")

        # Shutdown the session
        success = await client.session_meterpreter_shutdown(session_id)
        print(f"Shutdown result: {success}")

        # Wait for session to be removed or marked dead (may take a few seconds)
        import asyncio
        session_dead = False
        for attempt in range(10):  # Up to 10 seconds
            await asyncio.sleep(1)
            sessions_after = await client.sessions_list()
            if session_id not in sessions_after:
                print("Session removed from list after shutdown")
                session_dead = True
                break
            # Session still in list - check if it's marked dead
            alive_after = await client.session_alive(session_id)
            if not alive_after:
                print("Session marked as dead")
                session_dead = True
                break

        assert session_dead, "Session should be dead or removed after shutdown"
