"""High-performance IPC client for Metasploit Framework."""

from __future__ import annotations

import asyncio
from typing import Any

from ..log_config import PerformanceLogger, current_call_id, get_logger
from .errors import BufferEmptyError, RemoteError, TimeoutError
from .protocol import deserialize_response, serialize_call
from .shm import RingBuffer

logger = get_logger("ipc.client")


class MsfClient:
    """Async client for communicating with MSF daemon via IPC.

    This client provides a high-level async interface to the MSF daemon,
    handling all IPC details internally.

    Example:
        async with MsfClient() as client:
            version = await client.framework_version()
            print(f"MSF Version: {version}")
    """

    DEFAULT_SHM_NAME = "/assassinate_msf_ipc"
    DEFAULT_BUFFER_SIZE = 8 * 1024 * 1024  # 8 MB (optimized from 64MB)

    def __init__(
        self,
        shm_name: str = DEFAULT_SHM_NAME,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
    ):
        """Initialize the IPC client.

        Args:
            shm_name: Shared memory name (must match daemon)
            buffer_size: Ring buffer size (must match daemon)
        """
        self.shm_name = shm_name
        self.buffer_size = buffer_size
        self.request_buffer: RingBuffer | None = None  # Client writes requests
        self.response_buffer: RingBuffer | None = None  # Client reads responses
        self.next_call_id = 1
        self._pending_calls: dict[int, asyncio.Future] = {}
        self._response_reader_task: asyncio.Task | None = None
        self._shutdown = False

    async def connect(self) -> None:
        """Connect to the daemon's shared memory."""
        logger.info(
            f"Connecting to daemon: shm={self.shm_name}, "
            f"buffer_size={self.buffer_size}"
        )

        try:
            # Connect to both ring buffers (names must match daemon)
            request_name = f"{self.shm_name}_req"
            response_name = f"{self.shm_name}_resp"

            logger.debug(f"Opening request buffer: {request_name}")
            self.request_buffer = RingBuffer(request_name, self.buffer_size)

            logger.debug(f"Opening response buffer: {response_name}")
            self.response_buffer = RingBuffer(response_name, self.buffer_size)

            # Start background response reader task
            self._shutdown = False
            self._response_reader_task = asyncio.create_task(
                self._response_reader()
            )

            logger.info("Successfully connected to daemon")
        except Exception as e:
            logger.error(f"Failed to connect to daemon: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from shared memory."""
        logger.info("Disconnecting from daemon")

        # Signal shutdown and wait for response reader to finish
        self._shutdown = True
        if self._response_reader_task:
            try:
                await asyncio.wait_for(self._response_reader_task, timeout=2.0)
                logger.debug("Response reader task completed")
            except asyncio.TimeoutError:
                logger.warning("Response reader task timed out, cancelling")
                self._response_reader_task.cancel()
                try:
                    await self._response_reader_task
                except asyncio.CancelledError:
                    pass

        if self.request_buffer:
            self.request_buffer.close()
            self.request_buffer = None
        if self.response_buffer:
            self.response_buffer.close()
            self.response_buffer = None

        logger.info("Disconnected from daemon")

    async def __aenter__(self) -> MsfClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def _response_reader(self) -> None:
        """Background task that reads responses and routes to calls.

        This ensures responses are never lost, even if they arrive out of order.
        """
        logger.debug("Response reader task started")

        while not self._shutdown:
            try:
                # Try to read a response from the buffer
                if not self.response_buffer:
                    await asyncio.sleep(0.001)
                    continue

                response_bytes = self.response_buffer.try_read()
                response_call_id, result, error = deserialize_response(
                    response_bytes
                )

                # Find the pending call for this response
                future = self._pending_calls.pop(response_call_id, None)
                if future and not future.cancelled():
                    if error:
                        logger.debug(
                            f"Call {response_call_id} returned error: "
                            f"{error['code']}"
                        )
                        future.set_exception(
                            RemoteError(error["code"], error["message"])
                        )
                    else:
                        logger.debug(
                            f"Call {response_call_id} completed successfully"
                        )
                        future.set_result(result)
                elif not future:
                    logger.warning(
                        f"Received response for unknown "
                        f"call_id={response_call_id} (possibly timed out)"
                    )
                # If no pending call found, the response is silently dropped
                # (this could happen if a call timed out)

            except BufferEmptyError:
                # No data available - sleep briefly
                await asyncio.sleep(0.001)  # 1ms
            except Exception as e:
                # Log unexpected errors but keep running
                logger.error(f"Error in response reader: {e}", exc_info=True)
                await asyncio.sleep(0.01)

        logger.debug("Response reader task stopped")

    async def _call(self, method: str, *args: Any, timeout: float = 5.0) -> Any:
        """Make an RPC call to the daemon.

        Args:
            method: Method name to call
            *args: Method arguments
            timeout: Timeout in seconds

        Returns:
            Method result

        Raises:
            TimeoutError: If call times out
            RemoteError: If daemon returns an error
        """
        if not self.request_buffer or not self.response_buffer:
            raise RuntimeError("Not connected - call connect() first")

        # Generate call ID
        call_id = self.next_call_id
        self.next_call_id += 1

        # Set context for logging
        current_call_id.set(call_id)

        # Log the call with performance tracking
        args_summary = f"{len(args)} args" if args else "no args"
        logger.debug(f"Calling {method}({args_summary}) timeout={timeout}s")

        # Create a future for this call
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        self._pending_calls[call_id] = future

        try:
            with PerformanceLogger(logger, f"RPC {method}", call_id=call_id):
                # Serialize and send request
                request_bytes = serialize_call(call_id, method, list(args))
                self.request_buffer.try_write(request_bytes)

                # Wait for response with timeout
                # The response_reader task will set the result or exception
                result = await asyncio.wait_for(future, timeout=timeout)

            logger.info(f"Call {method} succeeded")
            return result

        except asyncio.TimeoutError:
            # Cleanup pending call on timeout
            self._pending_calls.pop(call_id, None)
            logger.error(f"Call {method} timed out after {timeout}s")
            raise TimeoutError(f"Call to {method} timed out after {timeout}s")
        except RemoteError as e:
            logger.error(
                f"Call {method} failed on daemon: {e.code} - {e.message}"
            )
            raise
        except Exception as e:
            # Cleanup on any other error
            self._pending_calls.pop(call_id, None)
            logger.error(f"Call {method} failed: {e}")
            raise
        finally:
            # Clear context
            current_call_id.set(None)

    # MSF API Methods

    async def framework_version(self) -> dict[str, str]:
        """Get the MSF framework version.

        Returns:
            Dictionary with version information
        """
        return await self._call("framework_version")

    async def list_modules(self, module_type: str) -> list[str]:
        """List all modules of a given type.

        Args:
            module_type: Type of modules to list (exploit, auxiliary,
                post, etc.)

        Returns:
            List of module names
        """
        result = await self._call("list_modules", module_type)
        return result.get("modules", [])

    async def search(self, query: str) -> list[str]:
        """Search for modules matching a query.

        Args:
            query: Search query string

        Returns:
            List of matching module names
        """
        result = await self._call("search", query)
        return result.get("results", [])

    async def get_module_info(self, module_name: str) -> dict[str, Any]:
        """Get detailed information about a module.

        Args:
            module_name: Full module name

        Returns:
            Dictionary with module information
        """
        return await self._call("get_module_info", module_name)

    async def threads(self) -> int:
        """Get the framework thread count.

        Returns:
            Number of threads
        """
        result = await self._call("threads")
        return result.get("threads", 0)

    async def list_sessions(self) -> list[int]:
        """List all active session IDs.

        Returns:
            List of session IDs
        """
        result = await self._call("list_sessions")
        return result.get("session_ids", [])

    # Module Management

    async def create_module(self, module_path: str) -> str:
        """Create a module instance.

        Args:
            module_path: Full module path (e.g.,
                "exploit/unix/ftp/vsftpd_backdoor")

        Returns:
            Module ID (handle for subsequent operations)
        """
        result = await self._call("create_module", module_path)
        return result["module_id"]

    async def module_info(self, module_id: str) -> dict[str, Any]:
        """Get module metadata.

        Args:
            module_id: Module ID from create_module

        Returns:
            Dictionary with name, fullname, type, description,
            etc.
        """
        return await self._call("module_info", module_id)

    async def module_options(self, module_id: str) -> str:
        """Get module options schema.

        Args:
            module_id: Module ID

        Returns:
            String representation of options
        """
        result = await self._call("module_options", module_id)
        return result["options"]

    async def module_set_option(
        self, module_id: str, key: str, value: str
    ) -> None:
        """Set a module option.

        Args:
            module_id: Module ID
            key: Option name
            value: Option value
        """
        await self._call("module_set_option", module_id, key, value)

    async def module_get_option(self, module_id: str, key: str) -> str | None:
        """Get a module option value.

        Args:
            module_id: Module ID
            key: Option name

        Returns:
            Option value or None
        """
        result = await self._call("module_get_option", module_id, key)
        return result.get("value")

    async def module_validate(self, module_id: str) -> bool:
        """Validate module configuration.

        Args:
            module_id: Module ID

        Returns:
            True if valid
        """
        result = await self._call("module_validate", module_id)
        return result["valid"]

    async def module_compatible_payloads(self, module_id: str) -> list[str]:
        """Get compatible payloads for an exploit.

        Args:
            module_id: Module ID (must be exploit)

        Returns:
            List of payload names
        """
        result = await self._call("module_compatible_payloads", module_id)
        return result["payloads"]

    async def module_actions(self, module_id: str) -> list[str]:
        """Get available actions for an auxiliary/post module.

        Args:
            module_id: Module ID (must be auxiliary or post)

        Returns:
            List of action names
        """
        result = await self._call("module_actions", module_id)
        return result["actions"]

    async def module_default_action(self, module_id: str) -> str | None:
        """Get the default action for an auxiliary/post module.

        Args:
            module_id: Module ID (must be auxiliary or post)

        Returns:
            Default action name, or None if module has no actions
        """
        result = await self._call("module_default_action", module_id)
        return result["default_action"]

    async def module_action(self, module_id: str) -> str | None:
        """Get the current action for an auxiliary/post module.

        This looks up datastore['ACTION'] and returns the matching action name.
        Falls back to default_action if ACTION is not set.

        Args:
            module_id: Module ID (must be auxiliary or post)

        Returns:
            Current action name, or None if module has no actions
        """
        result = await self._call("module_action", module_id)
        return result["action"]

    async def module_exploit(
        self,
        module_id: str,
        payload: str,
        options: dict[str, str] | None = None,
    ) -> int | None:
        """Execute an exploit module.

        Args:
            module_id: Module ID (must be exploit)
            payload: Payload to use
            options: Additional options to set before execution

        Returns:
            Session ID if successful, None otherwise
        """
        result = await self._call("module_exploit", module_id, payload, options)
        return result.get("session_id")

    async def module_run(
        self, module_id: str, options: dict[str, str] | None = None
    ) -> bool:
        """Execute an auxiliary module.

        Args:
            module_id: Module ID (must be auxiliary)
            options: Additional options to set before execution

        Returns:
            True if successful
        """
        result = await self._call("module_run", module_id, options)
        return result["success"]

    async def module_check(self, module_id: str) -> str:
        """Check if target is vulnerable.

        Args:
            module_id: Module ID

        Returns:
            Check result string
        """
        result = await self._call("module_check", module_id)
        return result["check_result"]

    async def module_has_check(self, module_id: str) -> bool:
        """Check if module supports vulnerability checking.

        Args:
            module_id: Module ID

        Returns:
            True if module has check method
        """
        result = await self._call("module_has_check", module_id)
        return result["has_check"]

    async def module_targets(self, module_id: str) -> list[str]:
        """Get exploit targets.

        Args:
            module_id: Module ID (must be exploit)

        Returns:
            List of target names
        """
        result = await self._call("module_targets", module_id)
        return result["targets"]

    async def module_aliases(self, module_id: str) -> list[str]:
        """Get module aliases.

        Args:
            module_id: Module ID

        Returns:
            List of alias names
        """
        result = await self._call("module_aliases", module_id)
        return result["aliases"]

    async def module_notes(self, module_id: str) -> dict[str, str]:
        """Get module notes.

        Args:
            module_id: Module ID

        Returns:
            Dictionary of notes
        """
        result = await self._call("module_notes", module_id)
        return result["notes"]

    async def delete_module(self, module_id: str) -> bool:
        """Delete a module instance to free memory.

        Args:
            module_id: Module ID to delete

        Returns:
            True if module was deleted, False if it didn't exist
        """
        result = await self._call("delete_module", module_id)
        return result["deleted"]

    # DataStore operations
    async def framework_get_option(self, key: str) -> str | None:
        """Get framework-level datastore option."""
        result = await self._call("framework_get_option", key)
        return result.get("value")

    async def framework_set_option(self, key: str, value: str) -> None:
        """Set framework-level datastore option."""
        await self._call("framework_set_option", key, value)

    async def framework_datastore_to_dict(self) -> dict[str, str]:
        """Get all framework datastore options as dict."""
        result = await self._call("framework_datastore_to_dict")
        return result["datastore"]

    async def framework_delete_option(self, key: str) -> None:
        """Delete framework datastore option."""
        await self._call("framework_delete_option", key)

    async def framework_clear_datastore(self) -> None:
        """Clear all framework datastore options."""
        await self._call("framework_clear_datastore")

    async def module_datastore_to_dict(self, module_id: str) -> dict[str, str]:
        """Get all module datastore options as dict."""
        result = await self._call("module_datastore_to_dict", module_id)
        return result["datastore"]

    async def module_delete_option(self, module_id: str, key: str) -> None:
        """Delete module datastore option."""
        await self._call("module_delete_option", module_id, key)

    async def module_clear_datastore(self, module_id: str) -> None:
        """Clear all module datastore options."""
        await self._call("module_clear_datastore", module_id)

    # PayloadGenerator operations
    async def payload_generate(
        self, payload_name: str, options: dict[str, str] | None = None
    ) -> bytes:
        """Generate a payload.

        Args:
            payload_name: Name of the payload (e.g.,
                "linux/x86/shell_reverse_tcp")
            options: Payload options/configuration

        Returns:
            Generated payload bytes
        """
        result = await self._call("payload_generate", payload_name, options)
        # Result is base64-encoded bytes
        import base64

        return base64.b64decode(result["payload"])

    async def payload_generate_encoded(
        self,
        payload_name: str,
        encoder: str | None = None,
        iterations: int | None = 1,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate an encoded payload.

        Args:
            payload_name: Name of the payload
            encoder: Encoder to use (e.g., "x86/shikata_ga_nai")
            iterations: Number of encoding iterations
            options: Payload options/configuration

        Returns:
            Encoded payload bytes
        """
        result = await self._call(
            "payload_generate_encoded",
            payload_name,
            encoder,
            iterations,
            options,
        )
        import base64

        return base64.b64decode(result["payload"])

    async def payload_list_payloads(self) -> list[str]:
        """List all available payloads.

        Returns:
            List of payload names
        """
        result = await self._call("payload_list_payloads")
        return result["payloads"]

    async def payload_generate_executable(
        self,
        payload_name: str,
        platform: str,
        arch: str,
        options: dict[str, str] | None = None,
    ) -> bytes:
        """Generate a standalone executable payload.

        Args:
            payload_name: Name of the payload
            platform: Target platform (e.g., "windows", "linux", "osx")
            arch: Target architecture (e.g., "x86", "x64", "x86_64")
            options: Payload options/configuration

        Returns:
            Executable payload bytes
        """
        result = await self._call(
            "payload_generate_executable", payload_name, platform, arch, options
        )
        import base64

        return base64.b64decode(result["executable"])

    # DbManager operations
    async def db_hosts(self) -> list[str]:
        """Get all hosts from the database.

        Returns:
            List of host IP addresses
        """
        result = await self._call("db_hosts")
        return result["hosts"]

    async def db_services(self) -> list[str]:
        """Get all services from the database.

        Returns:
            List of services
        """
        result = await self._call("db_services")
        return result["services"]

    async def db_report_host(self, options: dict[str, str]) -> int:
        """Report a host to the database.

        Args:
            options: Host options (host, os_name, os_flavor, etc.)

        Returns:
            Host ID
        """
        result = await self._call("db_report_host", options)
        return result["host_id"]

    async def db_report_service(self, options: dict[str, str]) -> int:
        """Report a service to the database.

        Args:
            options: Service options (host, port, proto, name, etc.)

        Returns:
            Service ID
        """
        result = await self._call("db_report_service", options)
        return result["service_id"]

    async def db_report_vuln(self, options: dict[str, str]) -> int:
        """Report a vulnerability to the database.

        Args:
            options: Vulnerability options (host, name, refs, info, etc.)

        Returns:
            Vulnerability ID
        """
        result = await self._call("db_report_vuln", options)
        return result["vuln_id"]

    async def db_report_cred(self, options: dict[str, str]) -> int:
        """Report a credential to the database.

        Args:
            options: Credential options (origin_type, address, port,
                username, etc.)

        Returns:
            Credential ID
        """
        result = await self._call("db_report_cred", options)
        return result["cred_id"]

    async def db_vulns(self) -> list[str]:
        """Get all vulnerabilities from the database.

        Returns:
            List of vulnerabilities
        """
        result = await self._call("db_vulns")
        return result["vulns"]

    async def db_creds(self) -> list[str]:
        """Get all credentials from the database.

        Returns:
            List of credentials
        """
        result = await self._call("db_creds")
        return result["creds"]

    async def db_loot(self) -> list[str]:
        """Get all loot from the database.

        Returns:
            List of loot items
        """
        result = await self._call("db_loot")
        return result["loot"]

    # JobManager operations
    async def job_list(self) -> list[str]:
        """List all active job IDs.

        Returns:
            List of job IDs
        """
        result = await self._call("job_list")
        return result["job_ids"]

    async def job_get(self, job_id: str) -> str | None:
        """Get job information by ID.

        Args:
            job_id: Job ID to retrieve

        Returns:
            Job information string or None if not found
        """
        result = await self._call("job_get", job_id)
        return result["job_info"]

    async def job_kill(self, job_id: str) -> bool:
        """Kill a running job.

        Args:
            job_id: Job ID to kill

        Returns:
            True if job was successfully killed
        """
        result = await self._call("job_kill", job_id)
        return result["success"]

    # PluginManager operations
    async def plugins_list(self) -> list[str]:
        """List loaded plugins.

        Returns:
            List of loaded plugin names
        """
        result = await self._call("plugins_list")
        return result["plugins"]

    async def plugins_load(
        self, path: str, options: dict[str, str] | None = None
    ) -> str:
        """Load a plugin from path.

        Args:
            path: Path to plugin file
            options: Optional plugin options

        Returns:
            Name of the loaded plugin
        """
        result = await self._call("plugins_load", path, options or {})
        return result["plugin_name"]

    async def plugins_unload(self, plugin_name: str) -> bool:
        """Unload a plugin by name.

        Args:
            plugin_name: Name of plugin to unload

        Returns:
            True if plugin was successfully unloaded
        """
        result = await self._call("plugins_unload", plugin_name)
        return result["success"]

    # SessionManager operations
    async def session_get(self, session_id: int) -> dict[str, Any] | None:
        """Get session details by ID.

        Args:
            session_id: Session ID to retrieve

        Returns:
            Session details dict or None if not found
        """
        result = await self._call("session_get", session_id)
        return result if result.get("session") is not None else result

    async def session_kill(self, session_id: int) -> bool:
        """Kill a session by ID.

        Args:
            session_id: Session ID to kill

        Returns:
            True if session was successfully killed
        """
        result = await self._call("session_kill", session_id)
        return result["success"]

    async def session_info(self, session_id: int) -> str | None:
        """Get session info string.

        Args:
            session_id: Session ID

        Returns:
            Info string or None if session not found
        """
        result = await self._call("session_info", session_id)
        return result["info"]

    async def session_type(self, session_id: int) -> str | None:
        """Get session type (shell, meterpreter, etc).

        Args:
            session_id: Session ID

        Returns:
            Session type string or None
        """
        result = await self._call("session_type", session_id)
        return result["type"]

    async def session_alive(self, session_id: int) -> bool:
        """Check if session is alive.

        Args:
            session_id: Session ID

        Returns:
            True if session is alive
        """
        result = await self._call("session_alive", session_id)
        return result["alive"]

    async def session_read(
        self, session_id: int, length: int | None = None
    ) -> str:
        """Read data from session.

        Args:
            session_id: Session ID
            length: Number of bytes to read (None = all available)

        Returns:
            Data read from session
        """
        result = await self._call("session_read", session_id, length)
        return result["data"]

    async def session_write(self, session_id: int, data: str) -> int:
        """Write data to session.

        Args:
            session_id: Session ID
            data: Data to write

        Returns:
            Number of bytes written
        """
        result = await self._call("session_write", session_id, data)
        return result["bytes_written"]

    async def session_execute(self, session_id: int, command: str) -> str:
        """Execute shell command in session.

        Args:
            session_id: Session ID
            command: Command to execute

        Returns:
            Command output
        """
        result = await self._call("session_execute", session_id, command)
        return result["output"]

    async def session_run_cmd(self, session_id: int, command: str) -> str:
        """Run meterpreter command in session.

        Args:
            session_id: Session ID
            command: Meterpreter command to run

        Returns:
            Command output
        """
        result = await self._call("session_run_cmd", session_id, command)
        return result["output"]

    async def session_desc(self, session_id: int) -> str | None:
        """Get session description.

        Args:
            session_id: Session ID

        Returns:
            Description string or None
        """
        result = await self._call("session_desc", session_id)
        return result["desc"]

    async def session_host(self, session_id: int) -> str | None:
        """Get session host.

        Args:
            session_id: Session ID

        Returns:
            Host string or None
        """
        result = await self._call("session_host", session_id)
        return result["host"]

    async def session_port(self, session_id: int) -> int | None:
        """Get session port.

        Args:
            session_id: Session ID

        Returns:
            Port number or None
        """
        result = await self._call("session_port", session_id)
        return result["port"]

    async def session_tunnel_peer(self, session_id: int) -> str | None:
        """Get tunnel peer (remote address).

        Args:
            session_id: Session ID

        Returns:
            Tunnel peer string or None
        """
        result = await self._call("session_tunnel_peer", session_id)
        return result["tunnel_peer"]

    async def session_target_host(self, session_id: int) -> str | None:
        """Get target host.

        Args:
            session_id: Session ID

        Returns:
            Target host string or None
        """
        result = await self._call("session_target_host", session_id)
        return result["target_host"]

    async def session_via_exploit(self, session_id: int) -> str | None:
        """Get exploit that created this session.

        Args:
            session_id: Session ID

        Returns:
            Exploit name or None
        """
        result = await self._call("session_via_exploit", session_id)
        return result["via_exploit"]

    async def session_via_payload(self, session_id: int) -> str | None:
        """Get payload that created this session.

        Args:
            session_id: Session ID

        Returns:
            Payload name or None
        """
        result = await self._call("session_via_payload", session_id)
        return result["via_payload"]

    # ========== Session Filesystem Operations (Meterpreter) ==========

    async def session_fs_pwd(self, session_id: int) -> str:
        """Get current working directory.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID

        Returns:
            Current working directory path
        """
        result = await self._call("session_fs_pwd", session_id)
        return result["pwd"]

    async def session_fs_chdir(self, session_id: int, path: str) -> None:
        """Change working directory.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: Directory path to change to
        """
        await self._call("session_fs_chdir", session_id, path)

    async def session_fs_ls(self, session_id: int, path: str) -> list[str]:
        """List directory contents.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: Directory path to list

        Returns:
            List of filenames
        """
        result = await self._call("session_fs_ls", session_id, path)
        return result["entries"]

    async def session_fs_mkdir(self, session_id: int, path: str) -> None:
        """Create directory.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: Directory path to create
        """
        await self._call("session_fs_mkdir", session_id, path)

    async def session_fs_rmdir(self, session_id: int, path: str) -> None:
        """Remove directory (must be empty).

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: Directory path to remove
        """
        await self._call("session_fs_rmdir", session_id, path)

    async def session_fs_stat(self, session_id: int, path: str) -> dict:
        """Get file/directory metadata.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: File or directory path

        Returns:
            Dict with file info: size, ftype, mtime, is_file, is_directory
        """
        result = await self._call("session_fs_stat", session_id, path)
        return result["stat"]

    async def session_fs_exists(self, session_id: int, path: str) -> bool:
        """Check if file or directory exists.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: File or directory path

        Returns:
            True if exists, False otherwise
        """
        result = await self._call("session_fs_exists", session_id, path)
        return result["exists"]

    async def session_fs_rm(self, session_id: int, path: str) -> None:
        """Delete file.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: File path to delete
        """
        await self._call("session_fs_rm", session_id, path)

    async def session_fs_mv(self, session_id: int, old_path: str, new_path: str) -> None:
        """Move/rename file.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            old_path: Source file path
            new_path: Destination file path
        """
        await self._call("session_fs_mv", session_id, old_path, new_path)

    async def session_fs_cp(self, session_id: int, src_path: str, dst_path: str) -> None:
        """Copy file.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            src_path: Source file path
            dst_path: Destination file path
        """
        await self._call("session_fs_cp", session_id, src_path, dst_path)

    async def session_fs_separator(self, session_id: int) -> str:
        """Get path separator for target system.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID

        Returns:
            Path separator ("\\" on Windows, "/" on Unix)
        """
        result = await self._call("session_fs_separator", session_id)
        return result["separator"]

    async def session_fs_expand_path(self, session_id: int, path: str) -> str:
        """Expand path (resolve environment variables).

        Resolves variables like %appdata%, $HOME, etc.
        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            path: Path with environment variables

        Returns:
            Expanded path
        """
        result = await self._call("session_fs_expand_path", session_id, path)
        return result["expanded_path"]

    async def session_fs_download_file(
        self, session_id: int, local_path: str, remote_path: str
    ) -> str:
        """Download file from remote to local.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            local_path: Local file path to save to
            remote_path: Remote file path to download

        Returns:
            Status string: "Completed", "Skipped", etc.
        """
        result = await self._call(
            "session_fs_download_file", session_id, local_path, remote_path
        )
        return result["status"]

    async def session_fs_upload_file(
        self, session_id: int, remote_path: str, local_path: str
    ) -> None:
        """Upload file from local to remote.

        Only works on Meterpreter sessions.

        Args:
            session_id: Session ID
            remote_path: Remote file path to save to
            local_path: Local file path to upload
        """
        await self._call("session_fs_upload_file", session_id, remote_path, local_path)

    # ========== Session Post Module Execution ==========

    async def session_run_post_module(
        self, session_id: int, module_path: str, options: dict[str, str] | None = None
    ) -> bool:
        """Run a post-exploitation module on a session.

        This is used for tasks like:
        - Upgrading shell to meterpreter: post/multi/manage/shell_to_meterpreter
        - Gathering credentials
        - Privilege escalation
        - Persistence

        The SESSION datastore option is automatically set to the specified session.

        Args:
            session_id: Session ID to run the module on
            module_path: Post module path (e.g., "post/multi/manage/shell_to_meterpreter")
            options: Optional dict of module options (e.g., {"LHOST": "192.168.1.100", "LPORT": "4444"})

        Returns:
            True if module ran successfully, False otherwise

        Example:
            # Upgrade a shell session to meterpreter
            success = await client.session_run_post_module(
                session_id=1,
                module_path="post/multi/manage/shell_to_meterpreter",
                options={"LHOST": "192.168.1.100", "LPORT": "4444"}
            )
        """
        result = await self._call(
            "session_run_post_module", session_id, module_path, options or {}
        )
        return result["success"]

    # ========== System Information Methods ==========

    async def session_sys_sysinfo(self, session_id: int) -> dict[str, Any]:
        """Get system information from a Meterpreter session.

        Returns information about the target system including OS, architecture,
        computer name, domain, and logged on users.

        Args:
            session_id: Session ID

        Returns:
            Dict with keys: Computer, OS, Architecture, BuildTuple,
            System Language, Domain, Logged On Users

        Example:
            info = await client.session_sys_sysinfo(1)
            print(f"OS: {info['OS']}")
            print(f"Architecture: {info['Architecture']}")
            print(f"Computer: {info['Computer']}")
        """
        result = await self._call("session_sys_sysinfo", session_id)
        return result["value"]

    async def session_sys_getuid(self, session_id: int) -> str:
        """Get the current username the session is running as.

        Args:
            session_id: Session ID

        Returns:
            Username string (e.g., "NT AUTHORITY\\SYSTEM" on Windows)

        Example:
            username = await client.session_sys_getuid(1)
            print(f"Running as: {username}")
        """
        result = await self._call("session_sys_getuid", session_id)
        return result["value"]

    async def session_sys_getsid(self, session_id: int) -> str:
        """Get the current process SID (Windows only).

        Args:
            session_id: Session ID

        Returns:
            SID string (e.g., "S-1-5-18" for SYSTEM)

        Example:
            sid = await client.session_sys_getsid(1)
            print(f"SID: {sid}")
        """
        result = await self._call("session_sys_getsid", session_id)
        return result["value"]

    async def session_sys_is_system(self, session_id: int) -> bool:
        """Check if the session is running as SYSTEM (Windows only).

        Args:
            session_id: Session ID

        Returns:
            True if running as SYSTEM, False otherwise

        Example:
            if await client.session_sys_is_system(1):
                print("Running as SYSTEM!")
        """
        result = await self._call("session_sys_is_system", session_id)
        return result["value"]

    async def session_sys_getenv(self, session_id: int, var_name: str) -> str | None:
        """Get an environment variable value from the target.

        Args:
            session_id: Session ID
            var_name: Environment variable name (e.g., "PATH")

        Returns:
            Variable value if found, None otherwise

        Example:
            path = await client.session_sys_getenv(1, "PATH")
            if path:
                print(f"PATH: {path}")
        """
        result = await self._call("session_sys_getenv", session_id, var_name)
        return result["value"]

    async def session_sys_getenvs(
        self, session_id: int, var_names: list[str]
    ) -> dict[str, str]:
        """Get multiple environment variables from the target.

        Args:
            session_id: Session ID
            var_names: List of variable names to retrieve

        Returns:
            Dict mapping variable names to values (missing vars omitted)

        Example:
            envs = await client.session_sys_getenvs(1, ["PATH", "HOME", "USER"])
            for name, value in envs.items():
                print(f"{name}: {value}")
        """
        result = await self._call("session_sys_getenvs", session_id, var_names)
        return result["value"]

    async def session_sys_localtime(self, session_id: int) -> str:
        """Get the local time on the target system.

        Args:
            session_id: Session ID

        Returns:
            Local time as a string

        Example:
            time = await client.session_sys_localtime(1)
            print(f"Target time: {time}")
        """
        result = await self._call("session_sys_localtime", session_id)
        return result["value"]

    async def session_sys_getdrivers(self, session_id: int) -> list[dict[str, str]]:
        """Get list of loaded drivers (Windows only).

        Args:
            session_id: Session ID

        Returns:
            List of dicts with keys: basename, filename

        Example:
            drivers = await client.session_sys_getdrivers(1)
            for driver in drivers[:5]:
                print(f"{driver['basename']}: {driver['filename']}")
        """
        result = await self._call("session_sys_getdrivers", session_id)
        return result["value"]

    async def session_sys_getprivs(self, session_id: int) -> list[str]:
        """Get list of enabled privileges (Windows only).

        Args:
            session_id: Session ID

        Returns:
            List of privilege names

        Example:
            privs = await client.session_sys_getprivs(1)
            print(f"Enabled privileges: {', '.join(privs)}")
        """
        result = await self._call("session_sys_getprivs", session_id)
        return result["value"]

    # ========== Network Configuration Methods ==========

    async def session_net_get_interfaces(self, session_id: int) -> list[dict[str, Any]]:
        """Get network interfaces from a Meterpreter session.

        Returns information about all network interfaces including IP addresses,
        MAC addresses, MTUs, and netmasks.

        Args:
            session_id: Session ID

        Returns:
            List of interface dicts with keys: index, mac_addr, mac_name,
            mtu, addrs (list), netmasks (list)

        Example:
            interfaces = await client.session_net_get_interfaces(1)
            for iface in interfaces:
                print(f"{iface['mac_name']}: {', '.join(iface['addrs'])}")
        """
        result = await self._call("session_net_get_interfaces", session_id)
        return result["value"]

    async def session_net_get_routes(self, session_id: int) -> list[dict[str, Any]]:
        """Get the routing table from a Meterpreter session.

        Args:
            session_id: Session ID

        Returns:
            List of route dicts with keys: subnet, netmask, gateway,
            interface, metric

        Example:
            routes = await client.session_net_get_routes(1)
            for route in routes:
                print(f"{route['subnet']} via {route['gateway']}")
        """
        result = await self._call("session_net_get_routes", session_id)
        return result["value"]

    async def session_net_get_arp_table(self, session_id: int) -> list[dict[str, str]]:
        """Get the ARP cache from a Meterpreter session.

        Args:
            session_id: Session ID

        Returns:
            List of ARP entry dicts with keys: ip_addr, mac_addr, interface

        Example:
            arp_table = await client.session_net_get_arp_table(1)
            for entry in arp_table:
                print(f"{entry['ip_addr']} -> {entry['mac_addr']}")
        """
        result = await self._call("session_net_get_arp_table", session_id)
        return result["value"]

    async def session_net_get_netstat(self, session_id: int) -> list[dict[str, Any]]:
        """Get network connections (netstat) from a Meterpreter session.

        Args:
            session_id: Session ID

        Returns:
            List of connection dicts with keys: local_addr, remote_addr,
            local_port, remote_port, protocol, state

        Example:
            connections = await client.session_net_get_netstat(1)
            for conn in connections:
                print(f"{conn['local_addr']}:{conn['local_port']} -> "
                      f"{conn['remote_addr']}:{conn['remote_port']} ({conn['state']})")
        """
        result = await self._call("session_net_get_netstat", session_id)
        return result["value"]

    async def session_net_add_route(
        self, session_id: int, subnet: str, netmask: str, gateway: str
    ) -> None:
        """Add a route to the routing table.

        Args:
            session_id: Session ID
            subnet: Subnet address (e.g., "192.168.1.0")
            netmask: Netmask (e.g., "255.255.255.0")
            gateway: Gateway address (e.g., "192.168.1.1")

        Example:
            await client.session_net_add_route(1, "10.0.0.0", "255.0.0.0", "192.168.1.1")
        """
        await self._call("session_net_add_route", session_id, subnet, netmask, gateway)

    async def session_net_remove_route(
        self, session_id: int, subnet: str, netmask: str, gateway: str
    ) -> None:
        """Remove a route from the routing table.

        Args:
            session_id: Session ID
            subnet: Subnet address (e.g., "192.168.1.0")
            netmask: Netmask (e.g., "255.255.255.0")
            gateway: Gateway address (e.g., "192.168.1.1")

        Example:
            await client.session_net_remove_route(1, "10.0.0.0", "255.0.0.0", "192.168.1.1")
        """
        await self._call(
            "session_net_remove_route", session_id, subnet, netmask, gateway
        )

    async def session_net_get_proxy_config(self, session_id: int) -> dict[str, Any]:
        """Get proxy configuration (Windows only).

        Args:
            session_id: Session ID

        Returns:
            Dict with keys: autodetect, autoconfigurl, proxy, proxybypass

        Example:
            proxy_config = await client.session_net_get_proxy_config(1)
            if proxy_config.get('proxy'):
                print(f"Proxy: {proxy_config['proxy']}")
        """
        result = await self._call("session_net_get_proxy_config", session_id)
        return result["value"]

    # ========== Shell Session Operations (Non-Meterpreter) ==========

    async def session_shell_read(self, session_id: int) -> str:
        """Read output from shell session (non-Meterpreter).

        Args:
            session_id: Session ID

        Returns:
            Output from shell session

        Example:
            output = await client.session_shell_read(1)
            print(f"Shell output: {output}")
        """
        result = await self._call("session_shell_read", session_id)
        return result["output"]

    async def session_shell_write(self, session_id: int, data: str) -> int:
        """Write input to shell session (non-Meterpreter).

        Args:
            session_id: Session ID
            data: Data to write to shell

        Returns:
            Number of bytes written

        Example:
            bytes_written = await client.session_shell_write(1, "whoami\\n")
            print(f"Wrote {bytes_written} bytes")
        """
        result = await self._call("session_shell_write", session_id, data)
        return result["bytes_written"]

    async def session_shell_to_meterpreter(
        self, session_id: int, lhost: str, lport: int
    ) -> bool:
        """Upgrade shell session to Meterpreter.

        Args:
            session_id: Session ID
            lhost: Local host IP for reverse connection
            lport: Local port for reverse connection

        Returns:
            True if upgrade was initiated successfully

        Example:
            success = await client.session_shell_to_meterpreter(1, "192.168.1.10", 4444)
            if success:
                print("Shell upgrade initiated")
        """
        result = await self._call("session_shell_to_meterpreter", session_id, lhost, lport)
        return result["success"]
