"""MSF DataStore implementation via IPC.

Provides key-value configuration storage for modules and framework settings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assassinate.ipc.client import MsfClient


class DataStore:
    """Key-value configuration store.

    Case-insensitive storage for module and framework options.
    Used to configure modules and framework settings.

    Note:
        Keys are case-insensitive: "RHOSTS", "rhosts", "RHosts" all access
        the same value.
        All methods are async since they use IPC.
    """

    def __init__(self, client: MsfClient, module_id: str | None = None) -> None:
        """Initialize DataStore wrapper.

        Args:
            client: Connected MsfClient instance.
            module_id: Optional module ID for module-specific datastore.
                      If None, uses framework global datastore.

        Note:
            This is called internally. Users should get DataStore instances
            via Framework.datastore() or Module.datastore().
        """
        self._client = client
        self._module_id = module_id

    async def get(self, key: str) -> str | None:
        """Get value by key.

        Args:
            key: Option name (case-insensitive).

        Returns:
            Value string or None if not set.

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> print(await ds.get("rhosts"))  # Case-insensitive
            192.168.1.100
        """
        if self._module_id:
            # Module-specific datastore
            return await self._client.module_get_option(self._module_id, key)
        else:
            # Framework global datastore
            return await self._client.framework_get_option(key)

    async def set(self, key: str, value: str) -> None:
        """Set value by key.

        Args:
            key: Option name (case-insensitive).
            value: Value to set.

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> await ds.set("rport", "21")  # Case-insensitive
        """
        if self._module_id:
            # Module-specific datastore
            await self._client.module_set_option(self._module_id, key, value)
        else:
            # Framework global datastore
            await self._client.framework_set_option(key, value)

    async def to_dict(self) -> dict[str, str]:
        """Convert datastore to a dictionary.

        Returns:
            Dictionary of all key-value pairs.

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> await ds.set("RPORT", "21")
            >>> print(await ds.to_dict())
            {'RHOSTS': '192.168.1.100', 'RPORT': '21'}
        """
        if self._module_id:
            return await self._client.module_datastore_to_dict(self._module_id)
        else:
            return await self._client.framework_datastore_to_dict()

    async def delete(self, key: str) -> None:
        """Delete a key from the datastore.

        Args:
            key: Option name to delete (case-insensitive).

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> await ds.delete("RHOSTS")
            >>> print(await ds.get("RHOSTS"))
            None
        """
        if self._module_id:
            await self._client.module_delete_option(self._module_id, key)
        else:
            await self._client.framework_delete_option(key)

    async def keys(self) -> list[str]:
        """Get all keys in the datastore.

        Returns:
            List of all keys.

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> await ds.set("RPORT", "21")
            >>> print(await ds.keys())
            ['RHOSTS', 'RPORT']
        """
        data = await self.to_dict()
        return list(data.keys())

    async def clear(self) -> None:
        """Clear all values from the datastore.

        Example:
            >>> ds = mod.datastore()
            >>> await ds.set("RHOSTS", "192.168.1.100")
            >>> await ds.clear()
            >>> print(await ds.to_dict())
            {}
        """
        if self._module_id:
            await self._client.module_clear_datastore(self._module_id)
        else:
            await self._client.framework_clear_datastore()

    def __repr__(self) -> str:
        """Return string representation of DataStore.

        Returns:
            String representation showing stored values.

        Note:
            This is a sync method and cannot fetch data.
            Use await ds.to_dict() to see current values.
        """
        scope = "module" if self._module_id else "framework"
        return f"<DataStore scope={scope}>"
