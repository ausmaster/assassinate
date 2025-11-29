"""MSF Module implementation via IPC.

Provides access to exploit, auxiliary, payload, and other MSF modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assassinate.ipc.client import MsfClient


class Module:
    """MSF module (exploit, auxiliary, payload, etc.).

    Represents a single MSF module instance with its configuration and
    execution methods.

    Note:
        Create via Framework.create_module(), not directly.
        All methods are async since they use IPC.
    """

    def __init__(self, module_id: str, client: MsfClient) -> None:
        """Initialize Module wrapper.

        Args:
            module_id: Unique module instance ID from daemon.
            client: Connected MsfClient instance.

        Note:
            This is called internally by Framework.create_module().
            Users should not call this directly.
        """
        self._module_id = module_id
        self._client = client

    async def name(self) -> str:
        """Get module name (short form).

        Returns:
            Module name without type prefix (e.g.,
            "vsftpd_234_backdoor").

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> print(await mod.name())
            vsftpd_234_backdoor
        """
        info = await self._client.module_info(self._module_id)
        return info["name"]

    async def fullname(self) -> str:
        """Get module full name.

        Returns:
            Full module path (e.g., "exploit/unix/ftp/vsftpd_234_backdoor").

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> print(await mod.fullname())
            exploit/unix/ftp/vsftpd_234_backdoor
        """
        info = await self._client.module_info(self._module_id)
        return info["fullname"]

    async def module_type(self) -> str:
        """Get module type.

        Returns:
            Type string (e.g., "exploit", "auxiliary", "payload").

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> print(await mod.module_type())
            exploit
        """
        info = await self._client.module_info(self._module_id)
        return info["type"]

    async def description(self) -> str:
        """Get module description.

        Returns:
            Human-readable description of what the module does.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> print(await mod.description())
            This module exploits a malicious backdoor...
        """
        info = await self._client.module_info(self._module_id)
        return info["description"]

    async def set_option(self, key: str, value: str) -> None:
        """Set a module option (convenience method).

        Args:
            key: Option name (case-insensitive).
            value: Option value.

        Raises:
            ValueError: If option is invalid.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> await mod.set_option("RHOSTS", "192.168.1.100")
            >>> await mod.set_option("RPORT", "21")
        """
        await self._client.module_set_option(self._module_id, key, value)

    async def get_option(self, key: str) -> str | None:
        """Get a module option value (convenience method).

        Args:
            key: Option name (case-insensitive).

        Returns:
            Option value or None if not set.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> await mod.set_option("RHOSTS", "192.168.1.100")
            >>> print(await mod.get_option("RHOSTS"))
            192.168.1.100
        """
        return await self._client.module_get_option(self._module_id, key)

    async def validate(self) -> bool:
        """Validate module configuration.

        Checks if all required options are set and valid.

        Returns:
            True if configuration is valid, False otherwise.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> await mod.set_option("RHOSTS", "192.168.1.100")
            >>> if await mod.validate():
            ...     print("Ready to run!")
        """
        return await self._client.module_validate(self._module_id)

    async def exploit(
        self,
        payload: str,
        options: dict[str, str] | None = None,
    ) -> int | None:
        """Execute an exploit module.

        Args:
            payload: Payload to use (e.g., "cmd/unix/reverse").
            options: Optional additional options to set before
                     execution.

        Returns:
            Session ID if successful, None if no session created.

        Raises:
            RuntimeError: If execution fails.
            ValueError: If module is not an exploit or config is
                        invalid.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> await mod.set_option("RHOSTS", "192.168.1.100")
            >>> session_id = await mod.exploit("cmd/unix/reverse")
            >>> if session_id:
            ...     print(f"Got session {session_id}")
        """
        return await self._client.module_exploit(
            self._module_id, payload, options
        )

    async def run(self, options: dict[str, str] | None = None) -> bool:
        """Execute an auxiliary module.

        Args:
            options: Optional additional options to set before
                     execution.

        Returns:
            True if successful, False otherwise.

        Raises:
            RuntimeError: If execution fails.
            ValueError: If module is not auxiliary or config is
                        invalid.

        Example:
            >>> mod = await fw.create_module("auxiliary/scanner/http/title")
            >>> await mod.set_option("RHOSTS", "192.168.1.1-254")
            >>> success = await mod.run()
        """
        return await self._client.module_run(self._module_id, options)

    async def check(self) -> str:
        """Check if target is vulnerable.

        Returns:
            Check result string (e.g., "Appears vulnerable", "Safe",
            "Unknown").

        Raises:
            RuntimeError: If check fails or module doesn't support
                          checking.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> await mod.set_option("RHOSTS", "192.168.1.100")
            >>> result = await mod.check()
            >>> print(result)
            Appears vulnerable
        """
        return await self._client.module_check(self._module_id)

    async def has_check(self) -> bool:
        """Check if module supports vulnerability checking.

        Returns:
            True if module has a check() method, False otherwise.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> if await mod.has_check():
            ...     result = await mod.check()
        """
        return await self._client.module_has_check(self._module_id)

    async def compatible_payloads(self) -> list[str]:
        """Get list of compatible payloads for this exploit.

        Returns:
            List of payload names that work with this exploit.

        Raises:
            ValueError: If module is not an exploit.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> payloads = await mod.compatible_payloads()
            >>> print(payloads[0])
            cmd/unix/reverse
        """
        return await self._client.module_compatible_payloads(self._module_id)

    async def author(self) -> list[str]:
        """Get module authors.

        Returns:
            List of author names/credits.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> authors = await mod.author()
            >>> print(authors[0])
            hdm <x@hdm.io>
        """
        info = await self._client.module_info(self._module_id)
        return info.get("author", [])

    async def references(self) -> list[str]:
        """Get module references (CVE, BID, URL, etc.).

        Returns:
            List of reference strings.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> refs = await mod.references()
            >>> for ref in refs:
            ...     print(ref)
        """
        info = await self._client.module_info(self._module_id)
        return info.get("references", [])

    async def options(self) -> str:
        """Get module options schema.

        Returns:
            String representation of OptionContainer.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> opts = await mod.options()
            >>> print(opts)
        """
        return await self._client.module_options(self._module_id)

    async def platform(self) -> list[str]:
        """Get target platforms.

        Returns:
            List of platform names (e.g., ["linux", "windows"]).

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> platforms = await mod.platform()
            >>> print(platforms)
            ['linux', 'unix']
        """
        info = await self._client.module_info(self._module_id)
        return info.get("platform", [])

    async def arch(self) -> list[str]:
        """Get target architectures.

        Returns:
            List of architecture names (e.g., ["x86", "x64"]).

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> archs = await mod.arch()
            >>> print(archs)
            ['x86']
        """
        info = await self._client.module_info(self._module_id)
        return info.get("arch", [])

    async def targets(self) -> list[str]:
        """Get exploit targets (for exploit modules only).

        Returns:
            List of target names.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/windows/smb/ms17_010_eternalblue"
            ... )
            >>> targets = await mod.targets()
            >>> for target in targets:
            ...     print(target)
        """
        return await self._client.module_targets(self._module_id)

    async def disclosure_date(self) -> str | None:
        """Get vulnerability disclosure date.

        Returns:
            Disclosure date string or None if not available.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> date = await mod.disclosure_date()
            >>> print(date)
            2011-07-04
        """
        info = await self._client.module_info(self._module_id)
        return info.get("disclosure_date")

    async def rank(self) -> str:
        """Get module rank.

        Returns:
            Rank string (e.g., "excellent", "great", "good", "normal",
            "average", "low", "manual").

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> rank = await mod.rank()
            >>> print(rank)
            excellent
        """
        info = await self._client.module_info(self._module_id)
        return info.get("rank", "")

    async def privileged(self) -> bool:
        """Check if module requires privileged access.

        Returns:
            True if module requires elevated privileges, False
            otherwise.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> is_priv = await mod.privileged()
            >>> print(f"Requires privileges: {is_priv}")
        """
        info = await self._client.module_info(self._module_id)
        return info.get("privileged", False)

    async def license(self) -> str:
        """Get module license.

        Returns:
            License string (typically "MSF_LICENSE" or similar).

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> lic = await mod.license()
            >>> print(lic)
        """
        info = await self._client.module_info(self._module_id)
        return info.get("license", "")

    async def aliases(self) -> list[str]:
        """Get module aliases.

        Returns:
            List of module alias names.

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> aliases = await mod.aliases()
            >>> print(f"Aliases: {aliases}")
        """
        return await self._client.module_aliases(self._module_id)

    async def notes(self) -> dict[str, str]:
        """Get module notes.

        Returns:
            Dictionary of note keys to values (reliability, stability,
            side effects, etc.).

        Example:
            >>> mod = await fw.create_module(
            ...     "exploit/unix/ftp/vsftpd_234_backdoor"
            ... )
            >>> notes = await mod.notes()
            >>> for key, value in notes.items():
            ...     print(f"{key}: {value}")
        """
        return await self._client.module_notes(self._module_id)

    def __repr__(self) -> str:
        """Return string representation of Module.

        Returns:
            String representation.
        """
        return f"<Module id={self._module_id}>"
