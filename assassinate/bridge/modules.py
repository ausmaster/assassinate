"""MSF Module implementation.

Provides access to exploit, auxiliary, payload, and other MSF modules.
"""

from __future__ import annotations

from typing import Any

from assassinate.bridge.datastore import DataStore


class Module:
    """MSF module (exploit, auxiliary, payload, etc.).

    Represents a single MSF module instance with its configuration and
    execution methods.

    Note:
        Create via Framework.create_module(), not directly.
    """

    _instance: Any  # The underlying PyO3 Module instance

    def __init__(self, instance: Any) -> None:
        """Initialize Module wrapper.

        Args:
            instance: PyO3 Module instance.

        Note:
            This is called internally by Framework.create_module().
            Users should not call this directly.
        """
        self._instance = instance

    def name(self) -> str:
        """Get module name (short form).

        Returns:
            Module name without type prefix (e.g., "vsftpd_234_backdoor").

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> print(mod.name())
            vsftpd_234_backdoor
        """
        return str(self._instance.name())

    def fullname(self) -> str:
        """Get module full name.

        Returns:
            Full module path (e.g., "exploit/unix/ftp/vsftpd_234_backdoor").

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> print(mod.fullname())
            exploit/unix/ftp/vsftpd_234_backdoor
        """
        return str(self._instance.fullname())

    def module_type(self) -> str:
        """Get module type.

        Returns:
            Type string (e.g., "exploit", "auxiliary", "payload").

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> print(mod.module_type())
            exploit
        """
        return str(self._instance.module_type())

    def description(self) -> str:
        """Get module description.

        Returns:
            Human-readable description of what the module does.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> print(mod.description())
            This module exploits a malicious backdoor...
        """
        return str(self._instance.description())

    def datastore(self) -> DataStore:
        """Get module datastore.

        Returns:
            Module-specific DataStore for configuration.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> ds = mod.datastore()
            >>> ds.set("RHOSTS", "192.168.1.100")
        """
        return DataStore(self._instance.datastore())

    def set_option(self, key: str, value: str) -> None:
        """Set a module option (convenience method).

        Args:
            key: Option name (case-insensitive).
            value: Option value.

        Raises:
            ValueError: If option is invalid.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> mod.set_option("RHOSTS", "192.168.1.100")
            >>> mod.set_option("RPORT", "21")
        """
        self._instance.set_option(key, value)

    def get_option(self, key: str) -> str | None:
        """Get a module option value (convenience method).

        Args:
            key: Option name (case-insensitive).

        Returns:
            Option value or None if not set.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> mod.set_option("RHOSTS", "192.168.1.100")
            >>> print(mod.get_option("RHOSTS"))
            192.168.1.100
        """
        result = self._instance.get_option(key)
        return str(result) if result is not None else None

    def validate(self) -> bool:
        """Validate module configuration.

        Checks if all required options are set and valid.

        Returns:
            True if configuration is valid, False otherwise.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> mod.set_option("RHOSTS", "192.168.1.100")
            >>> if mod.validate():
            ...     print("Ready to run!")
        """
        return bool(self._instance.validate())

    def exploit(
        self,
        payload: str,
        options: dict[str, str] | None = None,
    ) -> int | None:
        """Execute an exploit module.

        Args:
            payload: Payload to use (e.g., "cmd/unix/reverse").
            options: Optional additional options to set before execution.

        Returns:
            Session ID if successful, None if no session created.

        Raises:
            RuntimeError: If execution fails.
            ValueError: If module is not an exploit or config is invalid.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> mod.set_option("RHOSTS", "192.168.1.100")
            >>> session_id = mod.exploit("cmd/unix/reverse")
            >>> if session_id:
            ...     print(f"Got session {session_id}")
        """
        result = self._instance.exploit(payload, options)
        return int(result) if result is not None else None

    def run(self, options: dict[str, str] | None = None) -> bool:
        """Execute an auxiliary module.

        Args:
            options: Optional additional options to set before execution.

        Returns:
            True if successful, False otherwise.

        Raises:
            RuntimeError: If execution fails.
            ValueError: If module is not auxiliary or config is invalid.

        Example:
            >>> mod = fw.create_module("auxiliary/scanner/http/title")
            >>> mod.set_option("RHOSTS", "192.168.1.1-254")
            >>> success = mod.run()
        """
        return bool(self._instance.run(options))

    def check(self) -> str:
        """Check if target is vulnerable.

        Returns:
            Check result string (e.g., "Appears vulnerable", "Safe", "Unknown").

        Raises:
            RuntimeError: If check fails or module doesn't support checking.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> mod.set_option("RHOSTS", "192.168.1.100")
            >>> result = mod.check()
            >>> print(result)
            Appears vulnerable
        """
        return str(self._instance.check())

    def has_check(self) -> bool:
        """Check if module supports vulnerability checking.

        Returns:
            True if module has a check() method, False otherwise.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> if mod.has_check():
            ...     result = mod.check()
        """
        return bool(self._instance.has_check())

    def compatible_payloads(self) -> list[str]:
        """Get list of compatible payloads for this exploit.

        Returns:
            List of payload names that work with this exploit.

        Raises:
            ValueError: If module is not an exploit.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> payloads = mod.compatible_payloads()
            >>> print(payloads[0])
            cmd/unix/reverse
        """
        return list(self._instance.compatible_payloads())

    def author(self) -> list[str]:
        """Get module authors.

        Returns:
            List of author names/credits.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> authors = mod.author()
            >>> print(authors[0])
            hdm <x@hdm.io>
        """
        return list(self._instance.author())

    def references(self) -> list[str]:
        """Get module references (CVE, BID, URL, etc.).

        Returns:
            List of reference strings.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> refs = mod.references()
            >>> for ref in refs:
            ...     print(ref)
        """
        return list(self._instance.references())

    def options(self) -> str:
        """Get module options schema.

        Returns:
            String representation of OptionContainer.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> opts = mod.options()
            >>> print(opts)
        """
        return str(self._instance.options())

    def platform(self) -> list[str]:
        """Get target platforms.

        Returns:
            List of platform names (e.g., ["linux", "windows"]).

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> platforms = mod.platform()
            >>> print(platforms)
            ['linux', 'unix']
        """
        return list(self._instance.platform())

    def arch(self) -> list[str]:
        """Get target architectures.

        Returns:
            List of architecture names (e.g., ["x86", "x64"]).

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> archs = mod.arch()
            >>> print(archs)
            ['x86']
        """
        return list(self._instance.arch())

    def targets(self) -> list[str]:
        """Get exploit targets (for exploit modules only).

        Returns:
            List of target names.

        Example:
            >>> mod = fw.create_module("exploit/windows/smb/ms17_010_eternalblue")
            >>> targets = mod.targets()
            >>> for target in targets:
            ...     print(target)
        """
        return list(self._instance.targets())

    def disclosure_date(self) -> str | None:
        """Get vulnerability disclosure date.

        Returns:
            Disclosure date string or None if not available.

        Example:
            >>> mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> date = mod.disclosure_date()
            >>> print(date)
            2011-07-04
        """
        result = self._instance.disclosure_date()
        return str(result) if result is not None else None

    def __repr__(self) -> str:
        """Return string representation of Module.

        Returns:
            String representation.
        """
        return f"<Module {self.fullname()}>"
