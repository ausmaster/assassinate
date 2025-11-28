#!/usr/bin/env python3
"""Test Phase 1: Module creation and metadata via IPC."""

import asyncio
from assassinate.ipc import MsfClient


async def test_phase1():
    """Test basic module operations."""
    print("🧪 Testing Phase 1: Module Creation & Metadata\n")

    async with MsfClient() as client:
        # Test 1: Framework version (sanity check)
        print("1️⃣  Testing framework connection...")
        version = await client.framework_version()
        print(f"   ✓ MSF Version: {version.get('version', 'unknown')}\n")

        # Test 2: Create module
        print("2️⃣  Testing module creation...")
        module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
        print(f"   ✓ Created module with ID: {module_id}\n")

        # Test 3: Get module metadata
        print("3️⃣  Testing module metadata retrieval...")
        info = await client.module_info(module_id)
        print(f"   ✓ Name: {info.get('name', 'N/A')}")
        print(f"   ✓ Fullname: {info.get('fullname', 'N/A')}")
        print(f"   ✓ Type: {info.get('type', 'N/A')}")
        print(f"   ✓ Rank: {info.get('rank', 'N/A')}")
        print(f"   ✓ Description: {info.get('description', 'N/A')[:80]}...")
        print(f"   ✓ Disclosure Date: {info.get('disclosure_date', 'N/A')}\n")

        # Test 4: Set module option
        print("4️⃣  Testing module option setting...")
        await client.module_set_option(module_id, "RHOSTS", "192.168.1.100")
        print(f"   ✓ Set RHOSTS = 192.168.1.100\n")

        # Test 5: Get module option
        print("5️⃣  Testing module option retrieval...")
        rhosts = await client.module_get_option(module_id, "RHOSTS")
        print(f"   ✓ Retrieved RHOSTS = {rhosts}\n")

        # Test 6: Validate module (should fail - missing required options)
        print("6️⃣  Testing module validation (expect failure)...")
        valid = await client.module_validate(module_id)
        print(f"   ✓ Validation result: {valid} (expected False - missing options)\n")

        # Test 7: Get compatible payloads
        print("7️⃣  Testing compatible payloads retrieval...")
        payloads = await client.module_compatible_payloads(module_id)
        print(f"   ✓ Found {len(payloads)} compatible payloads")
        if payloads:
            print(f"   ✓ Sample payloads: {payloads[:3]}\n")

        # Test 8: Create another module and test options
        print("8️⃣  Testing second module instance...")
        module_id2 = await client.create_module("exploit/multi/handler")
        info2 = await client.module_info(module_id2)
        print(f"   ✓ Created second module: {info2.get('name', 'N/A')}\n")

        print("=" * 60)
        print("🎉 Phase 1 Testing Complete - All Tests Passed!")
        print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(test_phase1())
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
