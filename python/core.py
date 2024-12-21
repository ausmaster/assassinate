from __future__ import annotations
from ctypes import CDLL, c_bool, c_char_p
from json import loads, dumps


class MetasploitCore:
    """
    Python wrapper for the Metasploit Core shared library.
    Provides synchronous access to Metasploit functionalities via FFI.
    """

    def __init__(self, shared_library_path: str = "./metasploit_core.so") -> None:
        """
        Initialize the Metasploit Core wrapper.

        :param shared_library_path: Path to the compiled Metasploit shared library.
        :raises OSError: If the library fails to load.
        """
        try:
            self._msf = CDLL(shared_library_path)
        except OSError as e:
            raise OSError(f"Failed to load shared library: {e}")

        # Define return types for functions
        self._msf.init.restype = c_bool
        self._msf.get_version.restype = c_char_p
        self._msf.list_modules.restype = c_char_p
        self._msf.module_info.restype = c_char_p
        self._msf.run_module.restype = c_bool
        self._msf.create_console.restype = c_char_p
        self._msf.console_write.restype = c_bool
        self._msf.console_read.restype = c_char_p

        if not self._msf.init():
            raise RuntimeError("Failed to initialize Metasploit Core.")

    def get_version(self) -> str:
        """
        Retrieve the Metasploit version.

        :return: Version string.
        """
        version = self._msf.get_version()
        return version.decode()

    def list_modules(self, module_type: str) -> list:
        """
        List available Metasploit modules.

        :param module_type: Type of modules (e.g., "exploit", "payload").
        :return: List of module names.
        """
        modules = self._msf.list_modules(module_type.encode())
        return loads(modules.decode())

    def run_module(self, module_type: str, module_name: str, options: dict) -> bool:
        """
        Execute a Metasploit module.

        :param module_type: Type of the module.
        :param module_name: Name of the module.
        :param options: Dictionary of module options.
        :return: True if the module executes successfully.
        """
        options_json = dumps(options).encode()
        return self._msf.run_module(module_type.encode(), module_name.encode(), options_json)
