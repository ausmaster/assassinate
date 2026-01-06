"""Tests for Framework Routing operations.

These tests verify the Rex::Socket::SwitchBoard routing functionality,
which allows traffic to be routed through sessions (pivoting).

NOTE: Routing requires sessions created through exploits (not direct connections)
because MSF reports routes to the database, which requires session.db_record.

IMPORTANT: Uses a single comprehensive test because vsftpd backdoor only fires
once per container lifecycle. This pattern matches our Rust test approach.

Run with:
    docker exec dev pytest python/tests/test_routing.py -v
"""

import pytest


@pytest.mark.integration
class TestFrameworkRouting:
    """Test framework-level routing through sessions.

    Uses shell_session fixture (from vsftpd exploit) because routing
    requires proper DB-registered sessions.

    Single comprehensive test because vsftpd backdoor fires once per container.
    """

    @pytest.mark.asyncio
    async def test_route_operations(self, client, shell_session):
        """Test all route operations on a single session.

        This comprehensive test covers:
        - route_add (add a route)
        - route_exists (verify route exists)
        - route_list (list routes)
        - route_get (get best session for address)
        - route_remove (remove a route)
        - route_flush (flush all routes)
        - CIDR notation support
        - duplicate route handling
        """
        session_id = shell_session

        print("\n" + "=" * 60)
        print(" Route Management Comprehensive Test")
        print("=" * 60)

        # =====================================================================
        # Test 0: Basic session verification (since we have vsftpd session)
        # =====================================================================
        print("\n--- Test 0: Verify session basics ---")
        info = await client.session_info(session_id)
        print(f"Session info: {info}")
        assert info is not None, "Session info should not be None"

        session_type = await client.session_type(session_id)
        print(f"Session type: {session_type}")
        assert "shell" in session_type.lower() or "command" in session_type.lower()

        is_alive = await client.session_alive(session_id)
        print(f"Is alive: {is_alive}")
        assert is_alive is True, "Session should be alive"
        print("✓ Session basics verified")

        # =====================================================================
        # Test 1: Start with clean slate
        # =====================================================================
        print("\n--- Test 1: Flush existing routes ---")
        await client.route_flush()
        routes = await client.route_list()
        print(f"Routes after flush: {len(routes)}")
        assert len(routes) == 0, "Should start with no routes"
        print("✓ Routes flushed successfully")

        # =====================================================================
        # Test 2: Add a route
        # =====================================================================
        print("\n--- Test 2: route_add ---")
        result = await client.route_add("10.10.10.0", "255.255.255.0", session_id)
        print(f"route_add('10.10.10.0', '255.255.255.0', {session_id}) = {result}")
        assert result is True, "Route should be added successfully"
        print("✓ Route added")

        # =====================================================================
        # Test 3: Verify route exists
        # =====================================================================
        print("\n--- Test 3: route_exists ---")
        exists = await client.route_exists("10.10.10.0", "255.255.255.0")
        print(f"route_exists('10.10.10.0', '255.255.255.0') = {exists}")
        assert exists is True, "Route should exist"
        print("✓ Route exists check passed")

        # =====================================================================
        # Test 4: List routes
        # =====================================================================
        print("\n--- Test 4: route_list ---")
        routes = await client.route_list()
        print(f"Routes ({len(routes)} total):")
        for route in routes:
            print(f"  {route['subnet']}/{route['netmask']} via {route['comm_name']}")
        assert len(routes) == 1, "Should have exactly 1 route"
        assert routes[0]["subnet"] == "10.10.10.0"
        assert routes[0]["netmask"] == "255.255.255.0"
        assert routes[0]["session_id"] == session_id
        print("✓ Route list correct")

        # =====================================================================
        # Test 5: Get best session for address (route_get)
        # =====================================================================
        print("\n--- Test 5: route_get ---")
        best = await client.route_get("10.10.10.50")
        print(f"route_get('10.10.10.50') = {best}")
        assert best == session_id, f"Should route through session {session_id}"

        no_route = await client.route_get("192.168.1.1")
        print(f"route_get('192.168.1.1') = {no_route}")
        assert no_route is None, "Should not have route for unrouted address"
        print("✓ route_get works correctly")

        # =====================================================================
        # Test 6: Duplicate route handling
        # =====================================================================
        print("\n--- Test 6: Duplicate route handling ---")
        duplicate = await client.route_add("10.10.10.0", "255.255.255.0", session_id)
        print(f"Adding duplicate route: {duplicate}")
        assert duplicate is False, "Duplicate route should return False"
        print("✓ Duplicate handling correct")

        # =====================================================================
        # Test 7: Add route with CIDR notation
        # =====================================================================
        print("\n--- Test 7: CIDR notation ---")
        cidr_result = await client.route_add("172.16.0.0", "16", session_id)
        print(f"route_add('172.16.0.0', '16', {session_id}) = {cidr_result}")
        assert cidr_result is True, "CIDR route should be added"

        routes = await client.route_list()
        cidr_route = next((r for r in routes if r["subnet"] == "172.16.0.0"), None)
        assert cidr_route is not None, "CIDR route should exist"
        print(f"CIDR converted to: {cidr_route['netmask']}")
        assert cidr_route["netmask"] == "255.255.0.0", "CIDR /16 should be 255.255.0.0"
        print("✓ CIDR notation works")

        # =====================================================================
        # Test 8: Remove a specific route
        # =====================================================================
        print("\n--- Test 8: route_remove ---")
        removed = await client.route_remove("10.10.10.0", "255.255.255.0", session_id)
        print(f"route_remove('10.10.10.0', '255.255.255.0', {session_id}) = {removed}")
        assert removed is True, "Route should be removed"

        exists_after = await client.route_exists("10.10.10.0", "255.255.255.0")
        print(f"Route exists after removal: {exists_after}")
        assert exists_after is False, "Route should not exist after removal"
        print("✓ Route removed successfully")

        # =====================================================================
        # Test 9: Remove nonexistent route
        # =====================================================================
        print("\n--- Test 9: Remove nonexistent route ---")
        not_found = await client.route_remove("10.10.10.0", "255.255.255.0", session_id)
        print(f"Removing nonexistent route: {not_found}")
        assert not_found is False, "Removing nonexistent route should return False"
        print("✓ Nonexistent route handling correct")

        # =====================================================================
        # Test 10: Flush all routes
        # =====================================================================
        print("\n--- Test 10: route_flush ---")
        # Add a few more routes first
        await client.route_add("192.168.100.0", "255.255.255.0", session_id)

        routes_before = await client.route_list()
        print(f"Routes before flush: {len(routes_before)}")
        assert len(routes_before) >= 2, "Should have at least 2 routes"

        await client.route_flush()

        routes_after = await client.route_list()
        print(f"Routes after flush: {len(routes_after)}")
        assert len(routes_after) == 0, "All routes should be flushed"
        print("✓ Flush successful")

        print("\n" + "=" * 60)
        print(" All Route Management Tests Passed!")
        print("=" * 60)
