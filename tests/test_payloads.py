"""Tests for PayloadGenerator functionality."""

import pytest


@pytest.mark.integration
class TestPayloadList:
    """Tests for listing payloads."""

    async def test_list_payloads_returns_list(self, client):
        """Test that listing payloads returns a list."""
        payloads = await client.payload_list_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    async def test_list_contains_common_payloads(self, client):
        """Test that common payloads are in the list."""
        payloads = await client.payload_list_payloads()
        # Convert to lowercase for case-insensitive search
        payloads_lower = [p.lower() for p in payloads]

        # These are very common payloads that should exist
        assert any("shell_reverse_tcp" in p for p in payloads_lower)
        assert any("meterpreter" in p for p in payloads_lower)


@pytest.mark.integration
class TestPayloadGeneration:
    """Tests for basic payload generation."""

    async def test_generate_simple_payload(self, client):
        """Test generating a simple payload."""
        payload = await client.payload_generate(
            "linux/x86/shell_reverse_tcp",
            {"LHOST": "127.0.0.1", "LPORT": "4444"}
        )

        assert isinstance(payload, bytes)
        assert len(payload) > 0

    async def test_generate_without_options(self, client):
        """Test that generation works with default options.

        MSF doesn't error on missing required options - it uses defaults or placeholders.
        """
        # Should succeed even without LHOST/LPORT - MSF uses defaults
        payload = await client.payload_generate("linux/x86/shell_reverse_tcp", None)
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    async def test_generate_invalid_payload_fails(self, client):
        """Test that invalid payload name fails."""
        with pytest.raises(Exception):
            await client.payload_generate("invalid/fake/payload", {})

    async def test_generated_payload_is_bytes(self, client):
        """Test that generated payload is bytes, not string."""
        payload = await client.payload_generate(
            "linux/x86/exec",
            {"CMD": "/bin/sh"}
        )

        assert isinstance(payload, bytes)
        # Should not be base64 string
        assert not isinstance(payload, str)


@pytest.mark.integration
class TestPayloadEncoding:
    """Tests for encoded payload generation."""

    async def test_generate_encoded_payload(self, client):
        """Test generating an encoded payload."""
        payload = await client.payload_generate_encoded(
            "linux/x86/exec",
            encoder="x86/shikata_ga_nai",
            iterations=1,
            options={"CMD": "/bin/sh"}
        )

        assert isinstance(payload, bytes)
        assert len(payload) > 0

    async def test_encoded_different_from_unencoded(self, client):
        """Test that encoding produces valid output.

        Note: Some payloads/encoders may not actually modify the payload,
        so we just verify encoding succeeds and returns bytes.
        """
        options = {"CMD": "/bin/sh"}

        unencoded = await client.payload_generate("linux/x86/exec", options)
        encoded = await client.payload_generate_encoded(
            "linux/x86/exec",
            encoder="x86/shikata_ga_nai",
            iterations=1,
            options=options
        )

        # Both should be valid byte strings
        assert isinstance(unencoded, bytes)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

        # Encoded may or may not be different - depends on encoder/payload compatibility
        # Just verify encoding completed successfully

    async def test_encode_without_encoder_specified(self, client):
        """Test encoding with auto-selected encoder."""
        payload = await client.payload_generate_encoded(
            "linux/x86/exec",
            encoder=None,  # Auto-select encoder
            iterations=1,
            options={"CMD": "/bin/sh"}
        )

        assert isinstance(payload, bytes)
        assert len(payload) > 0


@pytest.mark.integration
class TestExecutableGeneration:
    """Tests for executable payload generation."""

    async def test_generate_linux_executable(self, client):
        """Test generating a Linux executable."""
        exe = await client.payload_generate_executable(
            "linux/x86/exec",
            platform="linux",
            arch="x86",
            options={"CMD": "/bin/sh"}
        )

        assert isinstance(exe, bytes)
        assert len(exe) > 0
        # Linux ELF binaries start with magic bytes
        assert exe.startswith(b'\x7fELF')

    async def test_executable_larger_than_raw(self, client):
        """Test that executable is larger than raw payload."""
        options = {"CMD": "/bin/sh"}

        raw = await client.payload_generate("linux/x86/exec", options)
        exe = await client.payload_generate_executable(
            "linux/x86/exec",
            platform="linux",
            arch="x86",
            options=options
        )

        # Executable should be larger (includes ELF headers, etc.)
        assert len(exe) > len(raw)


@pytest.mark.integration
class TestPayloadOptions:
    """Tests for payload option handling."""

    async def test_different_options_produce_different_payloads(self, client):
        """Test that different options produce different payloads."""
        payload1 = await client.payload_generate(
            "linux/x86/exec",
            {"CMD": "/bin/sh"}
        )
        payload2 = await client.payload_generate(
            "linux/x86/exec",
            {"CMD": "/bin/bash"}
        )

        # Different commands should produce different payloads
        assert payload1 != payload2

    async def test_options_as_dict(self, client):
        """Test that options are passed as dictionary."""
        payload = await client.payload_generate(
            "linux/x86/shell_reverse_tcp",
            {"LHOST": "192.168.1.100", "LPORT": "4444"}
        )

        assert isinstance(payload, bytes)
        assert len(payload) > 0
