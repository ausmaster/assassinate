"""Synchronous wrapper for async IPC client.

Provides a thread-safe synchronous interface to the async MsfClient by
running the event loop in a background thread.
"""

import asyncio
import atexit
import threading
from typing import Any

from assassinate.ipc.client import MsfClient


class SyncMsfClient:
    """Thread-safe synchronous wrapper for MsfClient.

    This class runs an event loop in a background thread and provides
    synchronous methods that delegate to the async client.

    Example:
        >>> client = SyncMsfClient()
        >>> client.connect()
        >>> version = client.framework_version()
        >>> print(version)
        {'version': '6.4.101-dev'}
        >>> client.disconnect()
    """

    def __init__(
        self, shm_name: str | None = None, buffer_size: int | None = None
    ):
        """Initialize sync client.

        Args:
            shm_name: Shared memory name (defaults to MsfClient.DEFAULT_SHM_NAME)
            buffer_size: Buffer size (defaults to MsfClient.DEFAULT_BUFFER_SIZE)
        """
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._async_client: MsfClient | None = None
        self._started = False
        self._lock = threading.Lock()

        # Store params for lazy initialization
        self._shm_name = shm_name or MsfClient.DEFAULT_SHM_NAME
        self._buffer_size = buffer_size or MsfClient.DEFAULT_BUFFER_SIZE

        # Register cleanup on exit
        atexit.register(self._cleanup)

    def _start_loop(self) -> None:
        """Start the background event loop thread."""
        with self._lock:
            if self._started:
                return

            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="AssassinateIPCThread"
            )
            self._thread.start()
            self._started = True

    def _run_loop(self) -> None:
        """Run the event loop in the background thread."""
        if self._loop is None:
            return
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro) -> Any:
        """Run a coroutine in the background thread and wait for result.

        Args:
            coro: Coroutine to run

        Returns:
            Result from the coroutine
        """
        if not self._started:
            self._start_loop()

        if self._loop is None:
            raise RuntimeError("Event loop not initialized")

        # Submit coroutine to background loop and wait for result
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def connect(self) -> None:
        """Connect to the daemon synchronously."""
        if not self._started:
            self._start_loop()

        if self._async_client is None:
            # Create client in background thread
            async def _create_and_connect():
                client = MsfClient(self._shm_name, self._buffer_size)
                await client.connect()
                return client

            self._async_client = self._run_coro(_create_and_connect())

    def disconnect(self) -> None:
        """Disconnect from the daemon synchronously."""
        if self._async_client:
            self._run_coro(self._async_client.disconnect())
            self._async_client = None

    def _cleanup(self) -> None:
        """Cleanup resources on exit."""
        if self._async_client:
            try:
                self.disconnect()
            except Exception:
                pass

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, *args):
        """Context manager exit."""
        self.disconnect()

    def _ensure_connected(self) -> MsfClient:
        """Ensure client is connected and return it."""
        if not self._async_client:
            raise RuntimeError("Not connected - call connect() first")
        return self._async_client

    # Framework Core Methods

    def framework_version(self) -> dict[str, str]:
        """Get framework version."""
        return self._run_coro(self._ensure_connected().framework_version())

    def list_modules(self, module_type: str) -> list[str]:
        """List modules of given type."""
        return self._run_coro(
            self._ensure_connected().list_modules(module_type)
        )

    def search(self, query: str) -> list[str]:
        """Search for modules."""
        return self._run_coro(self._ensure_connected().search(query))

    def get_module_info(self, module_name: str) -> dict[str, Any]:
        """Get detailed information about a module."""
        return self._run_coro(
            self._ensure_connected().get_module_info(module_name)
        )

    def threads(self) -> int:
        """Get thread count."""
        return self._run_coro(self._ensure_connected().threads())

    def list_sessions(self) -> list[int]:
        """List session IDs."""
        return self._run_coro(self._ensure_connected().list_sessions())

    # Module Management

    def create_module(self, module_path: str) -> str:
        """Create a module instance."""
        return self._run_coro(
            self._ensure_connected().create_module(module_path)
        )

    def module_info(self, module_id: str) -> dict[str, Any]:
        """Get module metadata."""
        return self._run_coro(self._ensure_connected().module_info(module_id))

    def module_options(self, module_id: str) -> str:
        """Get module options schema."""
        return self._run_coro(
            self._ensure_connected().module_options(module_id)
        )

    def module_set_option(self, module_id: str, key: str, value: str) -> None:
        """Set a module option."""
        self._run_coro(
            self._ensure_connected().module_set_option(module_id, key, value)
        )

    def module_get_option(self, module_id: str, key: str) -> str | None:
        """Get a module option value."""
        return self._run_coro(
            self._ensure_connected().module_get_option(module_id, key)
        )

    def module_validate(self, module_id: str) -> bool:
        """Validate module configuration."""
        return self._run_coro(
            self._ensure_connected().module_validate(module_id)
        )

    def module_compatible_payloads(self, module_id: str) -> list[str]:
        """Get compatible payloads for an exploit."""
        return self._run_coro(
            self._ensure_connected().module_compatible_payloads(module_id)
        )

    def module_exploit(
        self,
        module_id: str,
        payload: str,
        options: dict[str, str] | None = None,
    ) -> int | None:
        """Execute an exploit module."""
        return self._run_coro(
            self._ensure_connected().module_exploit(module_id, payload, options)
        )

    def module_run(
        self, module_id: str, options: dict[str, str] | None = None
    ) -> bool:
        """Execute an auxiliary module."""
        return self._run_coro(
            self._ensure_connected().module_run(module_id, options)
        )

    def module_check(self, module_id: str) -> str:
        """Check if target is vulnerable."""
        return self._run_coro(self._ensure_connected().module_check(module_id))

    def module_has_check(self, module_id: str) -> bool:
        """Check if module supports vulnerability checking."""
        return self._run_coro(
            self._ensure_connected().module_has_check(module_id)
        )

    def module_targets(self, module_id: str) -> list[str]:
        """Get available targets for the module."""
        return self._run_coro(
            self._ensure_connected().module_targets(module_id)
        )

    def module_aliases(self, module_id: str) -> list[str]:
        """Get module aliases."""
        return self._run_coro(
            self._ensure_connected().module_aliases(module_id)
        )

    def module_notes(self, module_id: str) -> dict[str, str]:
        """Get module notes."""
        return self._run_coro(self._ensure_connected().module_notes(module_id))

    def delete_module(self, module_id: str) -> bool:
        """Delete a module instance."""
        return self._run_coro(self._ensure_connected().delete_module(module_id))

    # Framework DataStore

    def framework_get_option(self, key: str) -> str | None:
        """Get framework option."""
        return self._run_coro(
            self._ensure_connected().framework_get_option(key)
        )

    def framework_set_option(self, key: str, value: str) -> None:
        """Set framework option."""
        self._run_coro(
            self._ensure_connected().framework_set_option(key, value)
        )

    def framework_datastore_to_dict(self) -> dict[str, str]:
        """Get all framework options as dict."""
        return self._run_coro(
            self._ensure_connected().framework_datastore_to_dict()
        )

    def framework_delete_option(self, key: str) -> None:
        """Delete framework option."""
        self._run_coro(self._ensure_connected().framework_delete_option(key))

    def framework_clear_datastore(self) -> None:
        """Clear all framework options."""
        self._run_coro(self._ensure_connected().framework_clear_datastore())

    # Module DataStore

    def module_datastore_to_dict(self, module_id: str) -> dict[str, str]:
        """Get all module options as dict."""
        return self._run_coro(
            self._ensure_connected().module_datastore_to_dict(module_id)
        )

    def module_delete_option(self, module_id: str, key: str) -> None:
        """Delete module option."""
        self._run_coro(
            self._ensure_connected().module_delete_option(module_id, key)
        )

    def module_clear_datastore(self, module_id: str) -> None:
        """Clear all module options."""
        self._run_coro(
            self._ensure_connected().module_clear_datastore(module_id)
        )

    # Payload Generation

    def payload_generate(
        self,
        payload_name: str,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate a payload."""
        return self._run_coro(
            self._ensure_connected().payload_generate(payload_name, options)
        )

    def payload_generate_encoded(
        self,
        payload_name: str,
        encoder: str | None = None,
        iterations: int | None = None,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate an encoded payload."""
        return self._run_coro(
            self._ensure_connected().payload_generate_encoded(
                payload_name, encoder, iterations, options
            )
        )

    def payload_list_payloads(self) -> list[str]:
        """List all available payloads."""
        return self._run_coro(self._ensure_connected().payload_list_payloads())

    def payload_generate_executable(
        self,
        payload_name: str,
        platform: str,
        arch: str,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate an executable payload."""
        return self._run_coro(
            self._ensure_connected().payload_generate_executable(
                payload_name, platform, arch, options
            )
        )

    # Database Operations

    def db_hosts(self) -> list[str]:
        """Get all hosts from database."""
        return self._run_coro(self._ensure_connected().db_hosts())

    def db_services(self) -> list[str]:
        """Get all services from database."""
        return self._run_coro(self._ensure_connected().db_services())

    def db_report_host(self, options: dict[str, str]) -> int:
        """Report a host to database."""
        return self._run_coro(self._ensure_connected().db_report_host(options))

    def db_report_service(self, options: dict[str, str]) -> int:
        """Report a service to database."""
        return self._run_coro(
            self._ensure_connected().db_report_service(options)
        )

    def db_report_vuln(self, options: dict[str, str]) -> int:
        """Report a vulnerability to database."""
        return self._run_coro(self._ensure_connected().db_report_vuln(options))

    def db_report_cred(self, options: dict[str, str]) -> int:
        """Report a credential to database."""
        return self._run_coro(self._ensure_connected().db_report_cred(options))

    def db_vulns(self) -> list[str]:
        """Get all vulnerabilities from database."""
        return self._run_coro(self._ensure_connected().db_vulns())

    def db_creds(self) -> list[str]:
        """Get all credentials from database."""
        return self._run_coro(self._ensure_connected().db_creds())

    def db_loot(self) -> list[str]:
        """Get all loot from database."""
        return self._run_coro(self._ensure_connected().db_loot())

    # Job Management

    def job_list(self) -> list[str]:
        """List all job IDs."""
        return self._run_coro(self._ensure_connected().job_list())

    def job_get(self, job_id: str) -> str | None:
        """Get job information."""
        return self._run_coro(self._ensure_connected().job_get(job_id))

    def job_kill(self, job_id: str) -> bool:
        """Kill a job."""
        return self._run_coro(self._ensure_connected().job_kill(job_id))

    # Plugin Management

    def plugins_list(self) -> list[str]:
        """List all loaded plugins."""
        return self._run_coro(self._ensure_connected().plugins_list())

    def plugins_load(
        self, path: str, options: dict[str, str] | None = None
    ) -> str:
        """Load a plugin."""
        return self._run_coro(
            self._ensure_connected().plugins_load(path, options)
        )

    def plugins_unload(self, plugin_name: str) -> bool:
        """Unload a plugin."""
        return self._run_coro(
            self._ensure_connected().plugins_unload(plugin_name)
        )

    # Session Management

    def session_get(self, session_id: int) -> dict[str, Any] | None:
        """Get session information."""
        return self._run_coro(self._ensure_connected().session_get(session_id))

    def session_kill(self, session_id: int) -> bool:
        """Kill a session."""
        return self._run_coro(self._ensure_connected().session_kill(session_id))

    def session_info(self, session_id: int) -> str | None:
        """Get session info string."""
        return self._run_coro(self._ensure_connected().session_info(session_id))

    def session_type(self, session_id: int) -> str | None:
        """Get session type."""
        return self._run_coro(self._ensure_connected().session_type(session_id))

    def session_alive(self, session_id: int) -> bool:
        """Check if session is alive."""
        return self._run_coro(
            self._ensure_connected().session_alive(session_id)
        )

    def session_read(self, session_id: int, length: int | None = None) -> str:
        """Read from session."""
        return self._run_coro(
            self._ensure_connected().session_read(session_id, length)
        )

    def session_write(self, session_id: int, data: str) -> int:
        """Write to session."""
        return self._run_coro(
            self._ensure_connected().session_write(session_id, data)
        )

    def session_execute(self, session_id: int, command: str) -> str:
        """Execute command in session."""
        return self._run_coro(
            self._ensure_connected().session_execute(session_id, command)
        )

    def session_run_cmd(self, session_id: int, command: str) -> str:
        """Run command in session."""
        return self._run_coro(
            self._ensure_connected().session_run_cmd(session_id, command)
        )

    def session_desc(self, session_id: int) -> str | None:
        """Get session description."""
        return self._run_coro(self._ensure_connected().session_desc(session_id))

    def session_host(self, session_id: int) -> str | None:
        """Get session host."""
        return self._run_coro(self._ensure_connected().session_host(session_id))

    def session_port(self, session_id: int) -> int | None:
        """Get session port."""
        return self._run_coro(self._ensure_connected().session_port(session_id))

    def session_tunnel_peer(self, session_id: int) -> str | None:
        """Get session tunnel peer."""
        return self._run_coro(
            self._ensure_connected().session_tunnel_peer(session_id)
        )

    def session_target_host(self, session_id: int) -> str | None:
        """Get session target host."""
        return self._run_coro(
            self._ensure_connected().session_target_host(session_id)
        )

    def session_via_exploit(self, session_id: int) -> str | None:
        """Get exploit that created session."""
        return self._run_coro(
            self._ensure_connected().session_via_exploit(session_id)
        )

    def session_via_payload(self, session_id: int) -> str | None:
        """Get payload that created session."""
        return self._run_coro(
            self._ensure_connected().session_via_payload(session_id)
        )

    # Async client access for advanced usage

    def get_async_client(self) -> MsfClient:
        """Get the underlying async client for advanced async usage.

        Warning: Only use this from async code running in the same event loop!

        Returns:
            The underlying MsfClient instance
        """
        return self._ensure_connected()
