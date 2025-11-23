from __future__ import annotations

from typing import ClassVar

class Bullet:
    """
    Abstract base class for bullet (payloads).

    :cvar name: Name of the bullet.
    :cvar description: Description of the bullet.
    :cvar supported_formats: List of supported output formats.
    """

    name: ClassVar[str] = "Base Bullet"
    description: ClassVar[str] = "Abstract base class for bullet (payloads)"
    supported_formats: ClassVar[list[str]] = []

    def load(self, **kwargs: str | int) -> bytes:
        """
        Generate the bullet (payload).

        :param kwargs: Arguments required for payload generation.
        :return: The generated payload as bytes.
        """
        raise NotImplementedError("Bullets must implement the load() method.")

    def chamber(self, raw_bullet: bytes, fmt: str = "raw") -> str | bytes:
        """
        Format the bullet for delivery.

        :param raw_bullet: The raw payload.
        :param fmt: Output format.
        :return: Formatted payload.
        """
        return raw_bullet
