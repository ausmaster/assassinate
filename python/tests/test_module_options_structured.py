"""Tests for module structured options and validation."""

import pytest


@pytest.mark.asyncio
async def test_module_options_structured(client):
    """Test getting structured options with full details."""
    print("\nTesting module_options_structured")

    # Create a module with known required options
    module_id = await client.create_module("auxiliary/scanner/portscan/tcp")
    print(f"   Created module: {module_id}")

    # Get structured options
    options = await client.module_options_structured(module_id)
    print(f"   ✓ Retrieved {len(options)} structured options")

    # Verify we got options
    assert len(options) > 0, "Should have options"

    # Check for common required option
    assert "RHOSTS" in options or "RHOST" in options, "Should have RHOSTS/RHOST option"

    # Verify option structure
    for opt_name, opt_details in options.items():
        assert isinstance(opt_details, dict), f"{opt_name} should have dict details"

        # Check for expected fields (may not all be present)
        if "required" in opt_details:
            assert isinstance(opt_details["required"], bool), f"{opt_name} required should be bool"

        if "desc" in opt_details:
            assert isinstance(opt_details["desc"], str), f"{opt_name} desc should be string"

        print(f"   {opt_name}: {opt_details.get('desc', 'N/A')[:50]}...")

    # Cleanup
    await client.delete_module(module_id)


@pytest.mark.asyncio
async def test_module_missing_required(client):
    """Test detecting missing required options."""
    print("\nTesting module_missing_required")

    # Create a module with required options
    module_id = await client.create_module("auxiliary/scanner/portscan/tcp")
    print(f"   Created module: {module_id}")

    # Get missing required options (should have some since we haven't configured anything)
    missing = await client.module_missing_required(module_id)
    print(f"   ✓ Missing required options: {missing}")

    # Should have at least RHOSTS missing
    assert len(missing) > 0, "Should have missing required options when unconfigured"
    assert "RHOSTS" in missing or "RHOST" in missing, "Should be missing RHOSTS/RHOST"

    # Now set RHOSTS
    await client.module_set_option(module_id, "RHOSTS", "192.168.1.1")

    # Check again
    missing_after = await client.module_missing_required(module_id)
    print(f"   After setting RHOSTS: {missing_after}")

    # RHOSTS should no longer be in missing list
    assert "RHOSTS" not in missing_after and "RHOST" not in missing_after, \
        "RHOSTS should not be missing after being set"

    # Cleanup
    await client.delete_module(module_id)


@pytest.mark.asyncio
async def test_structured_options_details(client):
    """Test that structured options provide useful details."""
    print("\nTesting structured option details")

    module_id = await client.create_module("exploit/windows/smb/ms17_010_eternalblue")
    print(f"   Created exploit module: {module_id}")

    options = await client.module_options_structured(module_id)

    # Find RHOST option and verify it has details
    if "RHOST" in options:
        rhost = options["RHOST"]
        print(f"   RHOST option: {rhost}")

        # Should have required field
        assert "required" in rhost, "RHOST should have 'required' field"
        assert rhost["required"] is True, "RHOST should be required"

        # Should have description
        if "desc" in rhost:
            print(f"   ✓ Description: {rhost['desc']}")

    # Find PAYLOAD option if it exists
    if "PAYLOAD" in options:
        payload = options["PAYLOAD"]
        print(f"   PAYLOAD option: {payload}")

    print(f"   ✓ Verified structured option details for {len(options)} options")

    await client.delete_module(module_id)


@pytest.mark.asyncio
async def test_missing_required_after_validate(client):
    """Test that missing_required aligns with validate."""
    print("\nTesting missing_required vs validate")

    module_id = await client.create_module("auxiliary/scanner/portscan/tcp")

    # Check validation (should fail)
    is_valid = await client.module_validate(module_id)
    print(f"   Validation without options: {is_valid}")

    # Get missing required
    missing = await client.module_missing_required(module_id)
    print(f"   Missing required: {missing}")

    # If validate is False, should have missing options
    if not is_valid:
        assert len(missing) > 0, "If validation fails, should have missing required options"
        print("   ✓ Validation and missing_required are consistent")

    await client.delete_module(module_id)
