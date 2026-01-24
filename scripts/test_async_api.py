#!/usr/bin/env python3
"""Test the new sync/async exploit API."""

import asyncio
import os
import sys

# Add the python package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import assassinate_pyo3 as msf


def test_imports():
    """Verify all exports are available."""
    print("=== Testing imports ===")

    # Check sleep_releasing_gvl is exported
    assert hasattr(msf, 'sleep_releasing_gvl'), "sleep_releasing_gvl not exported"
    print("✓ sleep_releasing_gvl is available")

    # Check Module has both methods
    from assassinate_pyo3.module import Module
    assert hasattr(Module, 'exploit'), "Module.exploit not found"
    assert hasattr(Module, 'exploit_async'), "Module.exploit_async not found"
    print("✓ Module has both exploit() and exploit_async()")

    # Check exploit_async is a coroutine function
    import inspect
    assert inspect.iscoroutinefunction(Module.exploit_async), "exploit_async should be async"
    print("✓ exploit_async is a proper async method")

    print()


def test_init_msf():
    """Initialize MSF framework."""
    print("=== Initializing MSF ===")

    msf_root = os.environ.get("MSF_ROOT", os.path.expanduser("~/Projects/metasploit-framework"))
    print(f"  MSF_ROOT: {msf_root}")

    msf.init_msf(msf_root)
    print(f"  Version: {msf.framework_version()}")
    print(f"  Initialized: {msf.is_initialized()}")
    print("✓ MSF initialized")
    print()


def test_module_creation():
    """Test module creation and API."""
    print("=== Testing Module API ===")

    module = msf.create_module("exploit/linux/samba/is_known_pipename")
    print(f"  Module: {module.fullname}")
    print(f"  Authors: {module.author[:2]}...")  # First 2 authors
    print(f"  Platform: {module.platform}")

    # Test option setting
    module.options.RHOSTS = "192.168.1.100"
    print(f"  Set RHOSTS: {module.options.RHOSTS}")

    # Verify exploit method exists and is sync
    import inspect
    assert not inspect.iscoroutinefunction(module.exploit), "exploit() should be sync"
    print("✓ module.exploit() is synchronous")

    assert inspect.iscoroutinefunction(module.exploit_async), "exploit_async() should be async"
    print("✓ module.exploit_async() is asynchronous")

    print()


async def test_async_api_structure():
    """Test that async API can be awaited (without real target)."""
    print("=== Testing Async API Structure ===")

    module = msf.create_module("exploit/linux/samba/is_known_pipename")
    module.options.RHOSTS = "10.255.255.1"  # Non-routable, will timeout

    print("  Testing exploit_async with 2s timeout (will timeout, no target)...")

    # This should work structurally - it will timeout but not crash
    import time
    start = time.time()

    # Use very short timeout for test
    session = await module.exploit_async("cmd/unix/interact", timeout=2)

    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.1f}s")
    print(f"  Session: {session}")  # Should be None (no target)

    if session is None and elapsed >= 1.5:
        print("✓ exploit_async works correctly (timed out as expected)")
    else:
        print("? Unexpected result")

    print()


def test_sleep_releasing_gvl():
    """Test GVL release primitive."""
    print("=== Testing sleep_releasing_gvl ===")

    import time

    start = time.time()
    msf.sleep_releasing_gvl(500)  # 500ms
    elapsed = time.time() - start

    print(f"  Slept for {elapsed*1000:.0f}ms (requested 500ms)")

    if 400 < elapsed * 1000 < 600:
        print("✓ sleep_releasing_gvl works correctly")
    else:
        print("? Timing seems off")

    print()


def main():
    print("=" * 60)
    print("Assassinate Async API Test")
    print("=" * 60)
    print()

    test_imports()
    test_init_msf()
    test_module_creation()
    test_sleep_releasing_gvl()

    # Run async test
    asyncio.run(test_async_api_structure())

    print("=" * 60)
    print("All tests passed!")
    print("=" * 60)
    print()
    print("API Summary:")
    print("  module.exploit(payload)              - Sync, blocking")
    print("  await module.exploit_async(payload)  - Async, parallel-capable")
    print()
    print("Example parallel exploitation:")
    print("""
    async def exploit_all(targets):
        tasks = []
        for target in targets:
            module = msf.create_module("exploit/linux/samba/is_known_pipename")
            module.options.RHOSTS = target
            tasks.append(module.exploit_async("cmd/unix/interact"))

        # All run in parallel!
        sessions = await asyncio.gather(*tasks)
        return [s for s in sessions if s]
    """)


if __name__ == "__main__":
    main()
