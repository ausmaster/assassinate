"""MSF DataStore implementation.

Provides key-value configuration storage for modules and framework settings.
"""

from __future__ import annotations

from typing import Any


class DataStore:
    """Key-value configuration store.

    Case-insensitive storage for module and framework options.
    Used to configure modules and framework settings.

    Note:
        Keys are case-insensitive: "RHOSTS", "rhosts", "RHosts" all access
        the same value.
    """

    _instance: Any  # The underlying PyO3 DataStore instance

    def __init__(self, instance: Any) -> None:
        """Initialize DataStore wrapper.

        Args:
            instance: PyO3 DataStore instance.

        Note:
            This is called internally. Users should get DataStore instances
            via Framework.datastore() or Module.datastore().
        """
        self._instance = instance

    def get(self, key: str) -> str | None:
        """Get value by key.

        Args:
            key: Option name (case-insensitive).

        Returns:
            Value string or None if not set.

        Example:
            >>> ds = mod.datastore()
            >>> ds.set("RHOSTS", "192.168.1.100")
            >>> print(ds.get("rhosts"))  # Case-insensitive
            192.168.1.100
        """
        result = self._instance.get(key)
        return str(result) if result is not None else None

    def set(self, key: str, value: str) -> None:
        """Set value by key.

        Args:
            key: Option name (case-insensitive).
            value: Value to set.

        Example:
            >>> ds = mod.datastore()
            >>> ds.set("RHOSTS", "192.168.1.100")
            >>> ds.set("rport", "21")  # Case-insensitive
        """
        self._instance.set(key, value)

    def to_dict(self) -> dict[str, str]:
        """Convert datastore to a dictionary.

        Returns:
            Dictionary of all key-value pairs.

        Example:
            >>> ds = mod.datastore()
            >>> ds.set("RHOSTS", "192.168.1.100")
            >>> ds.set("RPORT", "21")
            >>> print(ds.to_dict())
            {'RHOSTS': '192.168.1.100', 'RPORT': '21'}
        """
        return dict(self._instance.to_dict())

    def __repr__(self) -> str:
        """Return string representation of DataStore.

        Returns:
            String representation showing stored values.
        """
        data = self.to_dict()
        return f"<DataStore {data}>"
