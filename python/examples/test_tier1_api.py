#!/usr/bin/env python3
"""Test Tier 1 API: Session metadata and framework search."""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import assassinate_pyo3 as msf


def main():
    msf_root = os.environ.get(
        "MSF_ROOT", os.path.expanduser("~/Projects/metasploit-framework")
    )
    msf.init_msf(msf_root)

    print("=== Tier 1 API Tests ===\n")

    # Test 1: Framework search
    print("1. Testing search()...")
    results = msf.search("samba")
    print(f"   Found {len(results)} modules matching 'samba'")
    assert len(results) > 0, "Should find samba modules"
    print(f"   First 3: {results[:3]}")

    # Test CVE search
    cve_results = msf.search("CVE-2017-7494")
    print(f"   Found {len(cve_results)} modules for CVE-2017-7494")
    assert len(cve_results) > 0, "Should find CVE modules"

    # Test empty search
    no_results = msf.search("xyznonexistent123")
    assert len(no_results) == 0, "Nonsense query should return empty"
    print("   Nonsense query correctly returned empty")
    print("   ✓ search() works\n")

    # Test 2: List sessions
    print("2. Testing list_sessions()...")
    sessions = msf.list_sessions()
    print(f"   Active sessions: {sessions}")
    print("   ✓ list_sessions() works\n")

    # Test 3: Get non-existent session (returns None)
    print("3. Testing get_session() with invalid ID...")
    session = msf.get_session(99999)
    assert session is None, "Should return None for invalid session"
    print("   ✓ get_session(99999) returned None\n")

    # Test 4: Kill non-existent session
    print("4. Testing kill_session() with invalid ID...")
    result = msf.kill_session(99999)
    assert result is False, "Should return False for invalid session"
    print("   ✓ kill_session(99999) returned False\n")

    # Test 5: Session wrapper class basics
    print("5. Testing Session wrapper class...")
    from assassinate_pyo3.session import Session

    # Verify Session class exists and has expected attributes
    expected_attrs = [
        "sid",
        "session_type",
        "info",
        "alive",
        "desc",
        "host",
        "port",
        "tunnel_peer",
        "target_host",
        "via_exploit",
        "via_payload",
        "run_cmd",
        "read",
        "write",
        "kill",
    ]
    for attr in expected_attrs:
        assert hasattr(Session, attr), f"Session should have {attr}"
    print(f"   ✓ Session wrapper has all {len(expected_attrs)} expected attributes\n")

    # Test 6: Session object API (if any sessions exist)
    print("6. Testing Session object API...")
    if sessions:
        session = msf.get_session(sessions[0])
        print(f"   Session type: {session.session_type}")
        print(f"   Session host: {session.host}")
        print(f"   Session port: {session.port}")
        print(f"   Session alive: {session.alive}")
        print(f"   Repr: {session}")
        print("   ✓ Session properties work")
    else:
        print("   (No active sessions to test - skipping property access)")
    print()

    # Test 7: Module.exploit() returns Session type
    print("7. Testing Module.exploit() signature...")
    module = msf.create_module("exploit/linux/samba/is_known_pipename")
    module.options.RHOSTS = "192.168.1.100"
    print(f"   Module: {module.fullname}")
    print(f"   RHOSTS: {module.options.RHOSTS}")

    # Check that exploit method exists and has proper signature
    import inspect

    sig = inspect.signature(module.exploit)
    params = list(sig.parameters.keys())
    assert "payload" in params, "exploit() should have payload param"
    assert "timeout" in params, "exploit() should have timeout param"
    print(f"   ✓ exploit() signature: {sig}")
    print("   (Can't actually exploit without target - API ready)\n")

    # Test 8: All exports are available
    print("8. Testing module exports...")
    expected_exports = [
        "AssassinateError",
        "Module",
        "Session",
        "check",
        "create_module",
        "exploit",
        "framework_version",
        "get_module_info",
        "get_session",
        "init_msf",
        "is_initialized",
        "kill_session",
        "list_modules",
        "list_sessions",
        "search",
    ]
    for export in expected_exports:
        assert hasattr(msf, export), f"Module should export {export}"
    print(f"   ✓ All {len(expected_exports)} exports available\n")

    print("=== All Tier 1 Tests Passed! ===")


if __name__ == "__main__":
    main()
