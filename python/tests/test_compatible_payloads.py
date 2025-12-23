"""Test compatible_payloads bug fix."""

import pytest


@pytest.mark.asyncio
async def test_compatible_payloads(client):
    """Test that compatible_payloads returns payload names correctly."""
    # Create a well-known exploit module
    module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

    # Get compatible payloads
    payloads = await client.module_compatible_payloads(module_id)

    # Should have payloads
    assert len(payloads) > 0, "compatible_payloads should return at least one payload"

    # All payloads should be strings
    for payload in payloads:
        assert isinstance(payload, str), f"Payload should be string, got {type(payload)}"
        assert "/" in payload, f"Payload should be a path like 'cmd/unix/reverse_bash', got {payload}"

    # Cleanup
    await client.delete_module(module_id)

    print(f"✅ Found {len(payloads)} compatible payloads")
    print(f"First few payloads: {payloads[:5]}")
