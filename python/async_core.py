from __future__ import annotations
import asyncio
from ctypes import CDLL, c_bool, c_char_p
from json import loads, dumps


class MetasploitCoreAsync:
    """
    Asynchronous Python wrapper for the Metasploit Core shared library.
    Provides non-blocking access to Metasploit functionalities via FFI.
    """

    def __init__(self, shared_library_path: str = "./metasploit_core.so") -> None:
        """
        Initialize the Metasploit Core wrapper asynchronously.

        :param shared_library_path: Path to the compiled Metasploit shared library.
        :raises OSError: If the library fails to load.
        """
        try:
            self._msf: CDLL = CDLL(shared_library_path)
        except OSError as e:
            raise OSError(f"Failed to load shared library: {e}")

        self._msf.init.restype = c_bool
        self._msf.get_version.restype = c_char_p
        self._msf.list_modules.restype = c_char_p
        self._msf.run_module.restype = c_bool

        if not self._msf.init():
            raise RuntimeError("Failed to initialize Metasploit Core.")

    async def get_version(self) -> str:
        """
        Retrieve the Metasploit version asynchronously.

        :return: Version string.
        """
        await asyncio.sleep(0)
        version: bytes = self._msf.get_version()
        return version.decode()

    async def list_modules(self, module_type: str) -> list:
        """
        List available Metasploit modules asynchronously.

        :param module_type: Type of modules (e.g., "exploit", "payload").
        :return: List of module names.
        """
        await asyncio.sleep(0)
        modules: bytes = self._msf.list_modules(module_type.encode())
        return loads(modules.decode())

    async def run_module(self, module_type: str, module_name: str, options: dict) -> bool:
        """
        Execute a Metasploit module asynchronously.

        :param module_type: Type of the module.
        :param module_name: Name of the module.
        :param options: Dictionary of module options.
        :return: True if the module executes successfully.
        """
        await asyncio.sleep(0)
        options_json: bytes = dumps(options).encode()
        return self._msf.run_module(module_type.encode(), module_name.encode(), options_json)
