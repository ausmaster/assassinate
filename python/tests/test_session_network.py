"""Test Meterpreter network configuration operations."""

import pytest


@pytest.mark.asyncio
async def test_session_network_config(client):
    """Test Meterpreter network configuration gathering.

    Note: This test requires an active Meterpreter session.
    If no sessions exist, the test will be skipped.
    """
    # Get active sessions
    session_ids = await client.list_sessions()

    if not session_ids:
        pytest.skip("No active sessions available for network config test")

    # Use first session
    session_id = session_ids[0]

    # Get session info to check if it's Meterpreter
    session_info = await client.session_get(session_id)
    session_type = session_info.get("type", "")

    if "meterpreter" not in session_type.lower():
        pytest.skip(f"Session {session_id} is not Meterpreter (type: {session_type})")

    print(
        f"\n✓ Testing with Meterpreter session {session_id} (type: {session_type})"
    )

    # Test 1: Get network interfaces
    interfaces = await client.session_net_get_interfaces(session_id)
    assert isinstance(interfaces, list), "interfaces should be a list"
    assert len(interfaces) > 0, "Should have at least one interface"
    print(f"  Network interfaces ({len(interfaces)} total):")
    for iface in interfaces[:3]:
        name = iface.get("mac_name", "unknown")
        addrs = iface.get("addrs", [])
        mac = iface.get("mac_addr", "unknown")
        print(f"    - {name}: {', '.join(addrs)} (MAC: {mac})")
    if len(interfaces) > 3:
        print(f"    ... and {len(interfaces) - 3} more")

    # Test 2: Get routing table
    routes = await client.session_net_get_routes(session_id)
    assert isinstance(routes, list), "routes should be a list"
    print(f"  Routing table ({len(routes)} entries):")
    for route in routes[:5]:
        subnet = route.get("subnet", "unknown")
        netmask = route.get("netmask", "unknown")
        gateway = route.get("gateway", "unknown")
        iface = route.get("interface", "unknown")
        print(f"    - {subnet}/{netmask} via {gateway} dev {iface}")
    if len(routes) > 5:
        print(f"    ... and {len(routes) - 5} more")

    # Test 3: Get ARP table
    try:
        arp_table = await client.session_net_get_arp_table(session_id)
        assert isinstance(arp_table, list), "arp_table should be a list"
        print(f"  ARP table ({len(arp_table)} entries):")
        for entry in arp_table[:5]:
            ip = entry.get("ip_addr", "unknown")
            mac = entry.get("mac_addr", "unknown")
            iface = entry.get("interface", "unknown")
            print(f"    - {ip} -> {mac} ({iface})")
        if len(arp_table) > 5:
            print(f"    ... and {len(arp_table) - 5} more")
    except Exception as e:
        print(f"  ARP table failed (may not be supported): {e}")

    # Test 4: Get network connections (netstat)
    try:
        connections = await client.session_net_get_netstat(session_id)
        assert isinstance(connections, list), "connections should be a list"
        print(f"  Active connections ({len(connections)} total):")
        for conn in connections[:5]:
            local_addr = conn.get("local_addr", "unknown")
            local_port = conn.get("local_port", 0)
            remote_addr = conn.get("remote_addr", "unknown")
            remote_port = conn.get("remote_port", 0)
            proto = conn.get("protocol", "unknown")
            state = conn.get("state", "unknown")
            print(
                f"    - {local_addr}:{local_port} -> {remote_addr}:{remote_port} "
                f"({proto}/{state})"
            )
        if len(connections) > 5:
            print(f"    ... and {len(connections) - 5} more")
    except Exception as e:
        print(f"  Netstat failed (may not be supported): {e}")

    # Test 5: Get proxy configuration (Windows only)
    try:
        proxy_config = await client.session_net_get_proxy_config(session_id)
        assert isinstance(proxy_config, dict), "proxy_config should be a dict"
        print("  Proxy configuration:")
        if proxy_config.get("proxy"):
            print(f"    Proxy: {proxy_config['proxy']}")
        if proxy_config.get("autodetect"):
            print(f"    Autodetect: {proxy_config['autodetect']}")
        if proxy_config.get("autoconfigurl"):
            print(f"    Autoconfig URL: {proxy_config['autoconfigurl']}")
        if not any(proxy_config.values()):
            print("    No proxy configured")
    except Exception as e:
        print(f"  Proxy config failed (expected on non-Windows): {e}")

    # Note: We don't test route add/remove as that would modify the target system
    # Those methods are available but should be tested manually in a controlled environment

    print("✓ Network configuration test completed successfully")
