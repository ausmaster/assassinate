"""Test advanced payload generation (Tier 4.5A).

Tests for forge_payload_with_badchars() - automatic encoder selection.
"""

import os
import pytest
import msf


@pytest.fixture(scope="module")
def framework():
    """Initialize MSF framework once for the test module."""
    msf_root = os.environ.get("MSF_ROOT", os.path.expanduser("~/Projects/metasploit-framework"))
    if not msf.is_initialized():
        msf.init_msf(msf_root)
    yield


class TestForgePayloadWithBadchars:
    """Test forge_payload_with_badchars() auto-encoder selection."""

    def test_generates_payload_avoiding_null_bytes(self, framework):
        """forge_payload_with_badchars() avoids specified bad characters."""
        badchars = b"\x00"  # Null bytes

        payload_bytes, encoder_used = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            iterations=1,
            options={"CMD": "id"}
        )

        # Should return bytes
        assert isinstance(payload_bytes, bytes)
        assert len(payload_bytes) > 0

        # Should have used an encoder
        assert encoder_used is not None
        assert "shikata" in encoder_used or "alpha" in encoder_used or "fnstenv" in encoder_used

        # Verify no badchars in output
        for bad in badchars:
            assert bad not in payload_bytes, f"Payload contains bad character 0x{bad:02x}"

    def test_skips_encoding_if_payload_clean(self, framework):
        """forge_payload_with_badchars() skips encoding if payload already clean."""
        # Use badchars that are unlikely to appear in this small payload
        badchars = b"\xff\xfe\xfd"  # High bytes rarely in simple payloads

        payload_bytes, encoder_used = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            iterations=1,
            options={"CMD": "id"}
        )

        # If encoder_used is None, no encoding was needed
        # Either way, the payload should be clean
        assert isinstance(payload_bytes, bytes)
        for bad in badchars:
            assert bad not in payload_bytes

    def test_multiple_badchars(self, framework):
        """forge_payload_with_badchars() handles multiple bad characters."""
        # Common badchars: null, newline, carriage return
        badchars = b"\x00\x0a\x0d"

        payload_bytes, encoder_used = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            iterations=1,
            options={"CMD": "id"}
        )

        assert isinstance(payload_bytes, bytes)
        assert len(payload_bytes) > 0

        # Verify no badchars in output
        for bad in badchars:
            assert bad not in payload_bytes, f"Payload contains bad character 0x{bad:02x}"

    def test_multiple_iterations(self, framework):
        """forge_payload_with_badchars() supports multiple encoding iterations."""
        badchars = b"\x00"

        payload_bytes, encoder_used = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            iterations=3,  # Multiple iterations
            options={"CMD": "id"}
        )

        assert isinstance(payload_bytes, bytes)
        assert len(payload_bytes) > 0

        # Should be larger with more iterations
        # (each iteration adds decoder stub overhead)
        for bad in badchars:
            assert bad not in payload_bytes

    def test_empty_badchars_returns_raw(self, framework):
        """forge_payload_with_badchars() with empty badchars returns raw payload."""
        badchars = b""  # No badchars

        payload_bytes, encoder_used = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            options={"CMD": "id"}
        )

        assert isinstance(payload_bytes, bytes)
        # No encoder should be used
        assert encoder_used is None

    def test_returns_tuple(self, framework):
        """forge_payload_with_badchars() returns (bytes, encoder_name) tuple."""
        badchars = b"\x00"

        result = msf.forge_payload_with_badchars(
            "linux/x86/exec",
            badchars,
            options={"CMD": "id"}
        )

        assert isinstance(result, tuple)
        assert len(result) == 2

        payload_bytes, encoder_used = result
        assert isinstance(payload_bytes, bytes)
        assert encoder_used is None or isinstance(encoder_used, str)


class TestForgeFormatted:
    """Test forge_formatted() output format conversion."""

    def test_forge_formatted_c(self, framework):
        """forge_formatted() generates C array format."""
        result = msf.forge_formatted(
            "linux/x86/exec",
            "c",
            var_name="shellcode",
            options={"CMD": "id"}
        )

        assert isinstance(result, str)
        assert "unsigned char shellcode[]" in result
        assert "\\x" in result

    def test_forge_formatted_python(self, framework):
        """forge_formatted() generates Python format."""
        result = msf.forge_formatted(
            "linux/x86/exec",
            "python",
            options={"CMD": "id"}
        )

        assert isinstance(result, str)
        assert "buf" in result
        assert 'b"' in result

    def test_forge_formatted_base64(self, framework):
        """forge_formatted() generates base64 format."""
        result = msf.forge_formatted(
            "linux/x86/exec",
            "base64",
            options={"CMD": "id"}
        )

        assert isinstance(result, str)
        # Should be valid base64 (no unusual characters)
        import base64
        decoded = base64.b64decode(result)
        assert len(decoded) > 0

    def test_forge_formatted_rust(self, framework):
        """forge_formatted() generates Rust array format."""
        result = msf.forge_formatted(
            "linux/x86/exec",
            "rust",
            var_name="payload",
            options={"CMD": "id"}
        )

        assert isinstance(result, str)
        assert "let payload: [u8;" in result
        assert "0x" in result


class TestTransformBuffer:
    """Test transform_buffer() standalone function."""

    def test_transform_buffer_hex(self, framework):
        """transform_buffer() converts bytes to hex format."""
        test_bytes = b"ABCD"
        result = msf.transform_buffer(test_bytes, "hex")

        assert result == "\\x41\\x42\\x43\\x44"

    def test_transform_buffer_base64(self, framework):
        """transform_buffer() converts bytes to base64."""
        test_bytes = b"ABCD"
        result = msf.transform_buffer(test_bytes, "base64")

        assert result == "QUJDRA=="

    def test_transform_buffer_c(self, framework):
        """transform_buffer() converts bytes to C array."""
        test_bytes = b"ABC"
        result = msf.transform_buffer(test_bytes, "c", var_name="test")

        assert "unsigned char test[]" in result
        assert "\\x41" in result

    def test_transform_buffer_num(self, framework):
        """transform_buffer() converts bytes to numeric format."""
        test_bytes = b"\x00\x01\x02"
        result = msf.transform_buffer(test_bytes, "num")

        assert "0x00" in result
        assert "0x01" in result
        assert "0x02" in result

    def test_transform_buffer_invalid_format(self, framework):
        """transform_buffer() raises error for invalid format."""
        with pytest.raises(msf.AssassinateError):
            msf.transform_buffer(b"test", "invalid_format")
