from __future__ import annotations

from .shells import LinuxX86ReverseShellBullet
from .base import Bullet

BULLETS: dict[str, Bullet] = {
    LinuxX86ReverseShellBullet.name: LinuxX86ReverseShellBullet(),
    # Add more bullet here
}

def list_bullets() -> list[tuple[str, str]]:
    """
    List all available bullet.

    :return: List of tuples (bullet name, description).
    """
    return [(name, obj.description) for name, obj in BULLETS.items()]

def get_bullet(name: str) -> Bullet | None:
    """
    Retrieve a bullet by name.

    :param name: Name of the bullet.
    :return: Bullet instance or None if not found.
    """
    return BULLETS.get(name)
