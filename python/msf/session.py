"""Pythonic wrapper for PySession with property-based access."""

from typing import Any, Dict, List, Optional


class Session:
    """
    Rich Python wrapper around MSF sessions.

    Provides intuitive property-based access to session metadata
    and methods for interacting with the compromised host.

    Example:
        session = msf.get_session(1)
        print(session.host)          # "192.168.1.100"
        print(session.session_type)  # "shell"
        print(session.alive)         # True

        # Execute commands
        output = session.run_cmd("whoami")
        print(output)  # "root"

        # Kill when done
        session.kill()
    """

    def __init__(self, rust_session):
        """Initialize wrapper around a PySession from Rust."""
        self._rust = rust_session

    # =========================================================================
    # Properties (Pythonic attribute access)
    # =========================================================================

    @property
    def sid(self) -> int:
        """Session ID."""
        return self._rust.sid()

    @property
    def session_type(self) -> str:
        """Session type (shell, meterpreter, etc.)."""
        return self._rust.session_type()

    @property
    def info(self) -> str:
        """Session info string."""
        return self._rust.info()

    @property
    def alive(self) -> bool:
        """True if session is still active."""
        return self._rust.alive()

    @property
    def desc(self) -> str:
        """Session description."""
        return self._rust.desc()

    @property
    def host(self) -> str:
        """Target host IP address."""
        return self._rust.session_host()

    @property
    def port(self) -> int:
        """Target port."""
        return self._rust.session_port()

    @property
    def tunnel_peer(self) -> str:
        """Tunnel peer address."""
        return self._rust.tunnel_peer()

    @property
    def target_host(self) -> str:
        """Target host."""
        return self._rust.target_host()

    @property
    def via_exploit(self) -> str:
        """Exploit that created this session."""
        return self._rust.via_exploit()

    @property
    def via_payload(self) -> str:
        """Payload used for this session."""
        return self._rust.via_payload()

    # =========================================================================
    # Shell Methods
    # =========================================================================

    def run_cmd(self, cmd: str, timeout: Optional[int] = None) -> str:
        """
        Execute a command and return the output.

        Args:
            cmd: Command to execute
            timeout: Optional timeout in seconds

        Returns:
            Command output as string
        """
        return self._rust.run_cmd(cmd, timeout)

    def read(self, length: Optional[int] = None) -> str:
        """Read available data from session."""
        return self._rust.read(length)

    def write(self, data: str) -> int:
        """
        Write data to session.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        return self._rust.write(data)

    def kill(self) -> None:
        """Kill this session."""
        self._rust.kill()

    def shell_read(self) -> str:
        """Read from shell session."""
        return self._rust.shell_read()

    def shell_write(self, data: str) -> int:
        """Write to shell session."""
        return self._rust.shell_write(data)

    def shell_to_meterpreter(self, lhost: str, lport: int) -> bool:
        """
        Upgrade a shell session to meterpreter.

        Args:
            lhost: Local host for meterpreter callback
            lport: Local port for meterpreter callback

        Returns:
            True if upgrade was initiated successfully
        """
        return self._rust.shell_to_meterpreter(lhost, lport)

    # =========================================================================
    # Meterpreter Filesystem Operations
    # =========================================================================

    def fs_pwd(self) -> str:
        """Get current working directory on target."""
        return self._rust.fs_pwd()

    def fs_chdir(self, path: str) -> None:
        """
        Change directory on target.

        Args:
            path: Directory path to change to
        """
        self._rust.fs_chdir(path)

    def fs_ls(self, path: str) -> List[str]:
        """
        List directory contents on target.

        Args:
            path: Directory path to list

        Returns:
            List of filenames in the directory
        """
        return self._rust.fs_ls(path)

    def fs_mkdir(self, path: str) -> None:
        """
        Create directory on target.

        Args:
            path: Directory path to create
        """
        self._rust.fs_mkdir(path)

    def fs_rmdir(self, path: str) -> None:
        """
        Remove directory on target.

        Args:
            path: Directory path to remove
        """
        self._rust.fs_rmdir(path)

    def fs_exists(self, path: str) -> bool:
        """
        Check if file/directory exists on target.

        Args:
            path: Path to check

        Returns:
            True if path exists
        """
        return self._rust.fs_exists(path)

    def fs_rm(self, path: str) -> None:
        """
        Remove file on target.

        Args:
            path: File path to remove
        """
        self._rust.fs_rm(path)

    def fs_mv(self, old_path: str, new_path: str) -> None:
        """
        Move/rename file on target.

        Args:
            old_path: Current file path
            new_path: New file path
        """
        self._rust.fs_mv(old_path, new_path)

    def fs_cp(self, src_path: str, dst_path: str) -> None:
        """
        Copy file on target.

        Args:
            src_path: Source file path
            dst_path: Destination file path
        """
        self._rust.fs_cp(src_path, dst_path)

    def fs_separator(self) -> str:
        """Get the path separator for target OS."""
        return self._rust.fs_separator()

    def fs_expand_path(self, path: str) -> str:
        """
        Expand environment variables in path on target.

        Args:
            path: Path with environment variables (e.g., %TEMP%)

        Returns:
            Expanded path
        """
        return self._rust.fs_expand_path(path)

    def fs_download_file(self, local_path: str, remote_path: str) -> str:
        """
        Download file from target to local machine.

        Args:
            local_path: Local destination path
            remote_path: Remote source path

        Returns:
            Path to downloaded file
        """
        return self._rust.fs_download_file(local_path, remote_path)

    def fs_upload_file(self, remote_path: str, local_path: str) -> None:
        """
        Upload file from local machine to target.

        Args:
            remote_path: Remote destination path
            local_path: Local source path
        """
        self._rust.fs_upload_file(remote_path, local_path)

    def fs_stat(self, path: str) -> Dict[str, Any]:
        """
        Get file stats on target.

        Args:
            path: File path to stat

        Returns:
            Dictionary with file stats (size, mode, mtime, etc.)
        """
        return self._rust.fs_stat(path)

    def fs_md5(self, path: str) -> str:
        """
        Get MD5 hash of remote file.

        Args:
            path: Remote file path

        Returns:
            MD5 hash as hex string
        """
        return self._rust.fs_md5(path)

    def fs_sha1(self, path: str) -> str:
        """
        Get SHA1 hash of remote file.

        Args:
            path: Remote file path

        Returns:
            SHA1 hash as hex string
        """
        return self._rust.fs_sha1(path)

    def fs_search(
        self, root: str, pattern: str, recurse: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for files matching a pattern on target.

        Args:
            root: Root directory to search from
            pattern: Glob pattern to match (e.g., "*.txt")
            recurse: Whether to search recursively (default: True)

        Returns:
            List of matching file dictionaries with path, name, size
        """
        return self._rust.fs_search(root, pattern, recurse)

    # =========================================================================
    # Meterpreter Process Operations
    # =========================================================================

    def process_getpid(self) -> int:
        """Get the PID of the meterpreter process on target."""
        return self._rust.process_getpid()

    def process_list(self) -> List[Dict[str, Any]]:
        """
        List running processes on target.

        Returns:
            List of process dictionaries with pid, name, user, etc.
        """
        return self._rust.process_list()

    def process_kill(self, pid: int) -> None:
        """
        Kill a process on target.

        Args:
            pid: Process ID to kill
        """
        self._rust.process_kill(pid)

    def process_open(self, pid: int, perms: int) -> int:
        """
        Open a process handle on target (Windows).

        Args:
            pid: Process ID to open
            perms: Permission flags

        Returns:
            Process handle
        """
        return self._rust.process_open(pid, perms)

    def process_execute(
        self,
        path: str,
        args: str,
        hidden: Optional[bool] = None,
        channelized: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Execute a process on target.

        Args:
            path: Path to executable
            args: Command-line arguments
            hidden: Whether to hide the window (default: False)
            channelized: Whether to capture output (default: False)

        Returns:
            Process info dictionary with pid, handle, channel
        """
        return self._rust.process_execute(path, args, hidden, channelized)

    # =========================================================================
    # Meterpreter System Operations
    # =========================================================================

    def sys_getuid(self) -> str:
        """Get current user ID on target."""
        return self._rust.sys_getuid()

    def sys_getsid(self) -> str:
        """Get current session ID on target (Windows)."""
        return self._rust.sys_getsid()

    def sys_is_system(self) -> bool:
        """Check if running as SYSTEM on target (Windows)."""
        return self._rust.sys_is_system()

    def sys_localtime(self) -> str:
        """Get local time on target."""
        return self._rust.sys_localtime()

    def sys_getprivs(self) -> List[str]:
        """Get current privileges on target (Windows)."""
        return self._rust.sys_getprivs()

    def sys_sysinfo(self) -> Dict[str, Any]:
        """
        Get system information from target.

        Returns:
            Dictionary with OS, architecture, hostname, domain, etc.
        """
        return self._rust.sys_sysinfo()

    def sys_steal_token(self, pid: int) -> bool:
        """
        Steal a process token on target (Windows).

        Args:
            pid: Process ID to steal token from

        Returns:
            True if successful
        """
        return self._rust.sys_steal_token(pid)

    def sys_getdrivers(self) -> List[Dict[str, Any]]:
        """Get list of loaded drivers on target (Windows)."""
        return self._rust.sys_getdrivers()

    def sys_getenv(self, var_name: str) -> Optional[str]:
        """
        Get an environment variable on target.

        Args:
            var_name: Environment variable name

        Returns:
            Variable value, or None if not set
        """
        return self._rust.sys_getenv(var_name)

    def sys_getenvs(self, var_names: List[str]) -> Dict[str, str]:
        """
        Get multiple environment variables on target.

        Args:
            var_names: List of environment variable names

        Returns:
            Dictionary mapping variable names to values
        """
        return self._rust.sys_getenvs(var_names)

    # =========================================================================
    # Meterpreter Network Operations
    # =========================================================================

    def net_get_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interfaces on target."""
        return self._rust.net_get_interfaces()

    def net_get_routes(self) -> List[Dict[str, Any]]:
        """Get routing table on target."""
        return self._rust.net_get_routes()

    def net_get_arp_table(self) -> List[Dict[str, Any]]:
        """Get ARP table on target."""
        return self._rust.net_get_arp_table()

    def net_get_netstat(self) -> List[Dict[str, Any]]:
        """Get network connections on target."""
        return self._rust.net_get_netstat()

    def net_get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration on target."""
        return self._rust.net_get_proxy_config()

    def net_add_route(self, subnet: str, netmask: str, gateway: str) -> None:
        """
        Add a route on target.

        Args:
            subnet: Destination subnet
            netmask: Subnet mask
            gateway: Gateway address
        """
        self._rust.net_add_route(subnet, netmask, gateway)

    def net_remove_route(self, subnet: str, netmask: str, gateway: str) -> None:
        """
        Remove a route on target.

        Args:
            subnet: Destination subnet
            netmask: Subnet mask
            gateway: Gateway address
        """
        self._rust.net_remove_route(subnet, netmask, gateway)

    # =========================================================================
    # Meterpreter Core Operations
    # =========================================================================

    def meterpreter_shutdown(self) -> bool:
        """Gracefully shutdown the meterpreter session."""
        return self._rust.meterpreter_shutdown()

    def meterpreter_use(self, extension_name: str) -> bool:
        """
        Load a meterpreter extension.

        Args:
            extension_name: Name of extension to load (e.g., "stdapi", "priv")

        Returns:
            True if extension loaded successfully
        """
        return self._rust.meterpreter_use(extension_name)

    def meterpreter_secure(self) -> bool:
        """Enable encrypted communication for session."""
        return self._rust.meterpreter_secure()

    def meterpreter_machine_id(self, timeout: Optional[int] = None) -> str:
        """
        Get the machine ID of the target.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Machine ID string
        """
        return self._rust.meterpreter_machine_id(timeout)

    def meterpreter_native_arch(self, timeout: Optional[int] = None) -> str:
        """
        Get the native architecture of the target.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Architecture string (e.g., "x64", "x86")
        """
        return self._rust.meterpreter_native_arch(timeout)

    def meterpreter_session_guid(self, timeout: Optional[int] = None) -> str:
        """
        Get the session GUID.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Session GUID string
        """
        return self._rust.meterpreter_session_guid(timeout)

    def meterpreter_migrate(
        self,
        target_pid: int,
        writable_dir: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> bool:
        """
        Migrate meterpreter to another process.

        Args:
            target_pid: Target process ID to migrate to
            writable_dir: Optional writable directory for migration
            timeout: Optional timeout in seconds

        Returns:
            True if migration was successful
        """
        return self._rust.meterpreter_migrate(target_pid, writable_dir, timeout)

    # =========================================================================
    # Meterpreter Transport Operations
    # =========================================================================

    def transport_list(self) -> Dict[str, Any]:
        """Get list of configured transports."""
        return self._rust.transport_list()

    def transport_sleep(self, seconds: int) -> bool:
        """
        Sleep the session for specified seconds.

        Args:
            seconds: Number of seconds to sleep

        Returns:
            True if sleep was initiated
        """
        return self._rust.transport_sleep(seconds)

    def transport_next(self) -> bool:
        """Switch to the next configured transport."""
        return self._rust.transport_next()

    def transport_prev(self) -> bool:
        """Switch to the previous configured transport."""
        return self._rust.transport_prev()

    def transport_add(
        self,
        transport: str,
        lport: int,
        lhost: Optional[str] = None,
        ua: Optional[str] = None,
        comm_timeout: Optional[int] = None,
        session_exp: Optional[int] = None,
        retry_total: Optional[int] = None,
        retry_wait: Optional[int] = None,
    ) -> bool:
        """
        Add a new transport to the session.

        Args:
            transport: Transport type (e.g., "reverse_tcp", "reverse_https")
            lport: Local port
            lhost: Local host (optional)
            ua: User agent for HTTP transports (optional)
            comm_timeout: Communication timeout (optional)
            session_exp: Session expiration (optional)
            retry_total: Total retry count (optional)
            retry_wait: Wait between retries (optional)

        Returns:
            True if transport was added
        """
        return self._rust.transport_add(
            transport,
            lport,
            lhost,
            ua,
            comm_timeout,
            session_exp,
            retry_total,
            retry_wait,
        )

    def transport_remove(
        self, transport: str, lport: int, lhost: Optional[str] = None
    ) -> bool:
        """
        Remove a transport from the session.

        Args:
            transport: Transport type
            lport: Local port
            lhost: Local host (optional)

        Returns:
            True if transport was removed
        """
        return self._rust.transport_remove(transport, lport, lhost)

    def transport_change(
        self, transport: str, lport: int, lhost: Optional[str] = None
    ) -> bool:
        """
        Change to a different transport.

        Args:
            transport: Transport type
            lport: Local port
            lhost: Local host (optional)

        Returns:
            True if transport change was initiated
        """
        return self._rust.transport_change(transport, lport, lhost)

    def set_transport_timeouts(
        self,
        session_exp: Optional[int] = None,
        comm_timeout: Optional[int] = None,
        retry_total: Optional[int] = None,
        retry_wait: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Set transport timeouts.

        Args:
            session_exp: Session expiration timeout
            comm_timeout: Communication timeout
            retry_total: Total retry count
            retry_wait: Wait between retries

        Returns:
            Dictionary with updated timeout values
        """
        return self._rust.set_transport_timeouts(
            session_exp, comm_timeout, retry_total, retry_wait
        )

    # =========================================================================
    # Response Timeout Configuration
    # =========================================================================

    def get_response_timeout(self) -> int:
        """Get the response timeout in seconds."""
        return self._rust.get_response_timeout()

    def set_response_timeout(self, timeout_secs: int) -> None:
        """
        Set the response timeout.

        Args:
            timeout_secs: Timeout in seconds
        """
        self._rust.set_response_timeout(timeout_secs)

    # =========================================================================
    # Post-Exploitation Module Execution
    # =========================================================================

    def run_post_module(
        self, module_path: str, options: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Run a post-exploitation module on this session.

        Args:
            module_path: Full module path (e.g., "post/multi/gather/env")
            options: Optional dictionary of module options

        Returns:
            True if module ran successfully
        """
        return self._rust.run_post_module(module_path, options)

    # =========================================================================
    # Magic Methods
    # =========================================================================

    def __repr__(self) -> str:
        try:
            return f"<Session {self.sid}: {self.session_type} @ {self.host}:{self.port}>"
        except Exception:
            return f"<Session {self._rust.sid()}>"

    def __bool__(self) -> bool:
        """Session is truthy if alive."""
        try:
            return self.alive
        except Exception:
            return False
