from __future__ import annotations
import asyncio
from python.core import MetasploitCore
from python.async_core import MetasploitCoreAsync
from python.exceptions import InitializationError, RPCError, ValidationError
from python.logger import logger
from python.utils import validate_json


class Assassinate:
    """
    Assassinate API provides both synchronous and asynchronous interaction
    with the Metasploit Core shared library.
    """

    def __init__(self, shared_library_path: str = "./metasploit_core.so") -> None:
        """
        Initialize both synchronous and asynchronous APIs.

        :param shared_library_path: Path to the Metasploit Core shared library.
        """
        try:
            self.core = MetasploitCore(shared_library_path)
            self.async_core = MetasploitCoreAsync(shared_library_path)
            logger.info("Successfully initialized Assassinate interface.")
        except InitializationError as e:
            logger.error(f"Initialization failed: {e}")
            raise

    def get_version(self) -> str:
        """
        Retrieve the Metasploit version.

        :return: Version string.
        """
        try:
            version = self.core.get_version()
            logger.info(f"Metasploit version: {version}")
            return version
        except RPCError as e:
            logger.error(f"Failed to fetch version: {e}")
            raise

    def list_modules(self, module_type: str) -> list:
        """
        List available modules.

        :param module_type: Module type (e.g., 'exploit', 'payload').
        :return: List of modules.
        """
        try:
            modules = self.core.list_modules(module_type)
            logger.info(f"Retrieved {len(modules)} modules of type '{module_type}'.")
            return modules
        except RPCError as e:
            logger.error(f"Failed to list modules: {e}")
            raise

    def run_module(self, module_type: str, module_name: str, options: dict) -> bool:
        """
        Run a module.

        :param module_type: Module type.
        :param module_name: Module name.
        :param options: Module options.
        :return: True if execution is successful.
        """
        try:
            validate_json(str(options))
            result = self.core.run_module(module_type, module_name, options)
            logger.info(f"Module '{module_name}' executed successfully.")
            return result
        except (RPCError, ValidationError) as e:
            logger.error(f"Failed to run module: {e}")
            raise

    async def async_get_version(self) -> str:
        """
        Asynchronously retrieve the Metasploit version.

        :return: Version string.
        """
        try:
            version = await self.async_core.get_version()
            logger.info(f"Async Metasploit version: {version}")
            return version
        except RPCError as e:
            logger.error(f"Async failed to fetch version: {e}")
            raise

    async def async_list_modules(self, module_type: str) -> list:
        """
        Asynchronously list available modules.

        :param module_type: Module type.
        :return: List of modules.
        """
        try:
            modules = await self.async_core.list_modules(module_type)
            logger.info(f"Async retrieved {len(modules)} modules of type '{module_type}'.")
            return modules
        except RPCError as e:
            logger.error(f"Async failed to list modules: {e}")
            raise

    async def async_run_module(self, module_type: str, module_name: str, options: dict) -> bool:
        """
        Asynchronously run a module.

        :param module_type: Module type.
        :param module_name: Module name.
        :param options: Module options.
        :return: True if execution is successful.
        """
        try:
            validate_json(str(options))
            result = await self.async_core.run_module(module_type, module_name, options)
            logger.info(f"Async module '{module_name}' executed successfully.")
            return result
        except (RPCError, ValidationError) as e:
            logger.error(f"Async failed to run module: {e}")
            raise


__all__ = ["Assassinate"]
