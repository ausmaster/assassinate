"""High-performance IPC client for Metasploit Framework."""

from __future__ import annotations

import asyncio
from typing import Any

from assassinate.ipc.errors import BufferEmptyError, RemoteError, TimeoutError
from assassinate.ipc.protocol import deserialize_response, serialize_call
from assassinate.ipc.shm import RingBuffer


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
    DEFAULT_BUFFER_SIZE = 64 * 1024 * 1024  # 64 MB

    def __init__(self, shm_name: str = DEFAULT_SHM_NAME, buffer_size: int = DEFAULT_BUFFER_SIZE):
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

    async def connect(self) -> None:
        """Connect to the daemon's shared memory."""
        # Connect to both ring buffers (names must match daemon)
        request_name = f"{self.shm_name}_req"
        response_name = f"{self.shm_name}_resp"
        self.request_buffer = RingBuffer(request_name, self.buffer_size)
        self.response_buffer = RingBuffer(response_name, self.buffer_size)

    async def disconnect(self) -> None:
        """Disconnect from shared memory."""
        if self.request_buffer:
            self.request_buffer.close()
            self.request_buffer = None
        if self.response_buffer:
            self.response_buffer.close()
            self.response_buffer = None

    async def __aenter__(self) -> MsfClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.disconnect()

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

        # Serialize and send request
        request_bytes = serialize_call(call_id, method, list(args))
        self.request_buffer.try_write(request_bytes)

        # Wait for response with timeout
        start_time = asyncio.get_event_loop().time()
        while True:
            try:
                # Try to read response
                response_bytes = self.response_buffer.try_read()
                response_call_id, result, error = deserialize_response(response_bytes)

                # Check if this is our response
                if response_call_id == call_id:
                    if error:
                        raise RemoteError(error["code"], error["message"])
                    return result

                # Not our response - put it back? For now just skip
                # In a real implementation we'd need a queue of responses

            except BufferEmptyError:
                # No data yet - check timeout
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed > timeout:
                    raise TimeoutError(f"Call to {method} timed out after {timeout}s")

                # Sleep briefly and retry
                await asyncio.sleep(0.001)  # 1ms

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
            module_type: Type of modules to list (exploit, auxiliary, post, etc.)

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
            module_path: Full module path (e.g., "exploit/unix/ftp/vsftpd_234_backdoor")
            
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
            Dictionary with name, fullname, type, description, etc.
        """
        return await self._call("module_info", module_id)

    async def module_options(self, module_id: str) -> dict[str, Any]:
        """Get module options schema.
        
        Args:
            module_id: Module ID
            
        Returns:
            Dictionary of options
        """
        return await self._call("module_options", module_id)

    async def module_set_option(self, module_id: str, key: str, value: str) -> None:
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

    async def module_exploit(self, module_id: str, payload: str, options: dict[str, str] | None = None) -> int | None:
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

    async def module_run(self, module_id: str, options: dict[str, str] | None = None) -> bool:
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
    async def payload_generate(self, payload_name: str, options: dict[str, str] | None = None) -> bytes:
        """Generate a payload.

        Args:
            payload_name: Name of the payload (e.g., "linux/x86/shell_reverse_tcp")
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
        options: dict[str, str] | None = None
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
        result = await self._call("payload_generate_encoded", payload_name, encoder, iterations, options)
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
        options: dict[str, str] | None = None
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
        result = await self._call("payload_generate_executable", payload_name, platform, arch, options)
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
            options: Credential options (origin_type, address, port, username, etc.)

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
