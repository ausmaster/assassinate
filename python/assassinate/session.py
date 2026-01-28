"""Pythonic wrapper for PySession with property-based access."""

import logging
from typing import Any, Callable, Dict, List, Optional

from .console import print_session

# Get logger for this module
logger = logging.getLogger("assassinate.session")


class Session:
    """
    Rich Python wrapper around MSF sessions.

    Provides intuitive property-based access to session metadata
    and methods for interacting with the compromised host.

    Example:
        session = assassinate.get_session(1)
        print(session.host)          # "192.168.1.100"
        print(session.session_type)  # "shell"
        print(session.alive)         # True

        # Execute commands
        output = session.run_cmd("whoami")
        print(output)  # "root"

        # Kill when done
        session.kill()
    """

    # Properties that never change after session creation
    _IMMUTABLE_PROPS = frozenset({
        'sid', 'session_type', 'via_exploit', 'via_payload', 'desc', 'info'
    })

    def __init__(self, rust_session):
        """Initialize wrapper around a PySession from Rust."""
        self._rust = rust_session
        # Cache for immutable session metadata - avoids repeated FFI calls
        self._cache: Dict[str, Any] = {}
        logger.debug(f"Session initialized: sid={rust_session.sid()}")

    def _get_cached(self, key: str, getter: Callable[[], Any]) -> Any:
        """Get a cached value, computing it on first access."""
        if key not in self._cache:
            self._cache[key] = getter()
        return self._cache[key]

    # =========================================================================
    # Properties (Pythonic attribute access)
    # Immutable properties are cached to avoid repeated FFI calls.
    # =========================================================================

    @property
    def sid(self) -> int:
        """Session ID (cached - never changes)."""
        return self._get_cached('sid', self._rust.sid)

    @property
    def session_type(self) -> str:
        """Session type (shell, meterpreter, etc.) - cached."""
        return self._get_cached('session_type', self._rust.session_type)

    @property
    def info(self) -> str:
        """Session info string (cached)."""
        return self._get_cached('info', self._rust.info)

    @property
    def alive(self) -> bool:
        """True if session is still active (NOT cached - can change)."""
        return self._rust.alive()

    @property
    def desc(self) -> str:
        """Session description (cached)."""
        return self._get_cached('desc', self._rust.desc)

    @property
    def host(self) -> str:
        """Target host IP address (cached)."""
        return self._get_cached('host', self._rust.session_host)

    @property
    def port(self) -> int:
        """Target port (cached)."""
        return self._get_cached('port', self._rust.session_port)

    @property
    def tunnel_peer(self) -> str:
        """Tunnel peer address (NOT cached - can change with transport)."""
        return self._rust.tunnel_peer()

    @property
    def target_host(self) -> str:
        """Target host (cached)."""
        return self._get_cached('target_host', self._rust.target_host)

    @property
    def via_exploit(self) -> str:
        """Exploit that created this session (cached)."""
        return self._get_cached('via_exploit', self._rust.via_exploit)

    @property
    def via_payload(self) -> str:
        """Payload used for this session (cached)."""
        return self._get_cached('via_payload', self._rust.via_payload)

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
        logger.debug(f"run_cmd() on session {self.sid}: {cmd[:50] + '...' if len(cmd) > 50 else cmd}")
        try:
            result = self._rust.run_cmd(cmd, timeout)
            logger.debug(f"run_cmd() returned {len(result)} chars")
            return result
        except Exception as e:
            logger.error(f"run_cmd() failed on session {self.sid}: {e}")
            raise

    def read(self, length: Optional[int] = None) -> str:
        """Read available data from session."""
        logger.debug(f"read() on session {self.sid} (length={length})")
        try:
            result = self._rust.read(length)
            logger.debug(f"read() returned {len(result)} chars")
            return result
        except Exception as e:
            logger.error(f"read() failed on session {self.sid}: {e}")
            raise

    def write(self, data: str) -> int:
        """
        Write data to session.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        logger.debug(f"write() on session {self.sid}: {len(data)} bytes")
        try:
            result = self._rust.write(data)
            logger.debug(f"write() wrote {result} bytes")
            return result
        except Exception as e:
            logger.error(f"write() failed on session {self.sid}: {e}")
            raise

    def kill(self) -> None:
        """Kill this session."""
        logger.info(f"Killing session {self.sid}")
        try:
            self._rust.kill()
            logger.info(f"Session {self.sid} killed")
        except Exception as e:
            logger.error(f"Failed to kill session {self.sid}: {e}")
            raise

    def shell_read(self) -> str:
        """Read from shell session."""
        logger.debug(f"shell_read() on session {self.sid}")
        try:
            result = self._rust.shell_read()
            logger.debug(f"shell_read() returned {len(result)} chars")
            return result
        except Exception as e:
            logger.error(f"shell_read() failed on session {self.sid}: {e}")
            raise

    def shell_write(self, data: str) -> int:
        """Write to shell session."""
        logger.debug(f"shell_write() on session {self.sid}: {len(data)} bytes")
        try:
            result = self._rust.shell_write(data)
            logger.debug(f"shell_write() wrote {result} bytes")
            return result
        except Exception as e:
            logger.error(f"shell_write() failed on session {self.sid}: {e}")
            raise

    def shell_to_meterpreter(self, lhost: str, lport: int) -> bool:
        """
        Upgrade a shell session to meterpreter.

        Args:
            lhost: Local host for meterpreter callback
            lport: Local port for meterpreter callback

        Returns:
            True if upgrade was initiated successfully
        """
        logger.info(
            f"Upgrading session {self.sid} to meterpreter (lhost={lhost}, lport={lport})"
        )
        try:
            result = self._rust.shell_to_meterpreter(lhost, lport)
            if result:
                logger.info(f"Meterpreter upgrade initiated for session {self.sid}")
            else:
                logger.warning(f"Meterpreter upgrade failed for session {self.sid}")
            return result
        except Exception as e:
            logger.error(f"Meterpreter upgrade error for session {self.sid}: {e}")
            raise

    # =========================================================================
    # Meterpreter Filesystem Operations
    # =========================================================================

    def fs_pwd(self) -> str:
        """Get current working directory on target."""
        logger.debug(f"fs_pwd() on session {self.sid}")
        result = self._rust.fs_pwd()
        logger.debug(f"fs_pwd() -> {result}")
        return result

    def fs_chdir(self, path: str) -> None:
        """
        Change directory on target.

        Args:
            path: Directory path to change to
        """
        logger.debug(f"fs_chdir({path}) on session {self.sid}")
        self._rust.fs_chdir(path)

    def fs_ls(self, path: str) -> List[str]:
        """
        List directory contents on target.

        Args:
            path: Directory path to list

        Returns:
            List of filenames in the directory
        """
        logger.debug(f"fs_ls({path}) on session {self.sid}")
        result = self._rust.fs_ls(path)
        logger.debug(f"fs_ls() returned {len(result)} entries")
        return result

    def fs_mkdir(self, path: str) -> None:
        """
        Create directory on target.

        Args:
            path: Directory path to create
        """
        logger.debug(f"fs_mkdir({path}) on session {self.sid}")
        self._rust.fs_mkdir(path)

    def fs_rmdir(self, path: str) -> None:
        """
        Remove directory on target.

        Args:
            path: Directory path to remove
        """
        logger.debug(f"fs_rmdir({path}) on session {self.sid}")
        self._rust.fs_rmdir(path)

    def fs_exists(self, path: str) -> bool:
        """
        Check if file/directory exists on target.

        Args:
            path: Path to check

        Returns:
            True if path exists
        """
        logger.debug(f"fs_exists({path}) on session {self.sid}")
        result = self._rust.fs_exists(path)
        logger.debug(f"fs_exists() -> {result}")
        return result

    def fs_rm(self, path: str) -> None:
        """
        Remove file on target.

        Args:
            path: File path to remove
        """
        logger.debug(f"fs_rm({path}) on session {self.sid}")
        self._rust.fs_rm(path)

    def fs_mv(self, old_path: str, new_path: str) -> None:
        """
        Move/rename file on target.

        Args:
            old_path: Current file path
            new_path: New file path
        """
        logger.debug(f"fs_mv({old_path}, {new_path}) on session {self.sid}")
        self._rust.fs_mv(old_path, new_path)

    def fs_cp(self, src_path: str, dst_path: str) -> None:
        """
        Copy file on target.

        Args:
            src_path: Source file path
            dst_path: Destination file path
        """
        logger.debug(f"fs_cp({src_path}, {dst_path}) on session {self.sid}")
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
        logger.debug(f"fs_expand_path({path}) on session {self.sid}")
        result = self._rust.fs_expand_path(path)
        logger.debug(f"fs_expand_path() -> {result}")
        return result

    def fs_download_file(self, local_path: str, remote_path: str) -> str:
        """
        Download file from target to local machine.

        Args:
            local_path: Local destination path
            remote_path: Remote source path

        Returns:
            Path to downloaded file
        """
        logger.info(
            f"Downloading file on session {self.sid}: {remote_path} -> {local_path}"
        )
        try:
            result = self._rust.fs_download_file(local_path, remote_path)
            logger.info(f"Downloaded file to: {result}")
            return result
        except Exception as e:
            logger.error(f"File download failed: {e}")
            raise

    def fs_upload_file(self, remote_path: str, local_path: str) -> None:
        """
        Upload file from local machine to target.

        Args:
            remote_path: Remote destination path
            local_path: Local source path
        """
        logger.info(
            f"Uploading file on session {self.sid}: {local_path} -> {remote_path}"
        )
        try:
            self._rust.fs_upload_file(remote_path, local_path)
            logger.info("File uploaded successfully")
        except Exception as e:
            logger.error(f"File upload failed: {e}")
            raise

    def fs_stat(self, path: str) -> Dict[str, Any]:
        """
        Get file stats on target.

        Args:
            path: File path to stat

        Returns:
            Dictionary with file stats (size, mode, mtime, etc.)
        """
        logger.debug(f"fs_stat({path}) on session {self.sid}")
        return self._rust.fs_stat(path)

    def fs_md5(self, path: str) -> str:
        """
        Get MD5 hash of remote file.

        Args:
            path: Remote file path

        Returns:
            MD5 hash as hex string
        """
        logger.debug(f"fs_md5({path}) on session {self.sid}")
        result = self._rust.fs_md5(path)
        logger.debug(f"fs_md5() -> {result}")
        return result

    def fs_sha1(self, path: str) -> str:
        """
        Get SHA1 hash of remote file.

        Args:
            path: Remote file path

        Returns:
            SHA1 hash as hex string
        """
        logger.debug(f"fs_sha1({path}) on session {self.sid}")
        result = self._rust.fs_sha1(path)
        logger.debug(f"fs_sha1() -> {result}")
        return result

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
        logger.debug(
            f"fs_search({root}, {pattern}, recurse={recurse}) on session {self.sid}"
        )
        result = self._rust.fs_search(root, pattern, recurse)
        logger.debug(f"fs_search() found {len(result)} files")
        return result

    # =========================================================================
    # Meterpreter Process Operations
    # =========================================================================

    def process_getpid(self) -> int:
        """Get the PID of the meterpreter process on target."""
        logger.debug(f"process_getpid() on session {self.sid}")
        pid = self._rust.process_getpid()
        logger.debug(f"process_getpid() -> {pid}")
        return pid

    def process_list(self) -> List[Dict[str, Any]]:
        """
        List running processes on target.

        Returns:
            List of process dictionaries with pid, name, user, etc.
        """
        logger.debug(f"process_list() on session {self.sid}")
        procs = self._rust.process_list()
        logger.debug(f"process_list() returned {len(procs)} processes")
        return procs

    def process_kill(self, pid: int) -> None:
        """
        Kill a process on target.

        Args:
            pid: Process ID to kill
        """
        logger.info(f"Killing process {pid} on session {self.sid}")
        try:
            self._rust.process_kill(pid)
            logger.info(f"Process {pid} killed")
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            raise

    def process_open(self, pid: int, perms: int) -> int:
        """
        Open a process handle on target (Windows).

        Args:
            pid: Process ID to open
            perms: Permission flags

        Returns:
            Process handle
        """
        logger.debug(f"process_open(pid={pid}, perms={perms}) on session {self.sid}")
        handle = self._rust.process_open(pid, perms)
        logger.debug(f"process_open() -> handle={handle}")
        return handle

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
        logger.info(
            f"Executing process on session {self.sid}: {path} {args[:50] + '...' if len(args) > 50 else args}"
        )
        try:
            result = self._rust.process_execute(path, args, hidden, channelized)
            logger.info(f"Process executed: pid={result.get('pid')}")
            return result
        except Exception as e:
            logger.error(f"Process execution failed: {e}")
            raise

    # =========================================================================
    # Meterpreter System Operations
    # =========================================================================

    def sys_getuid(self) -> str:
        """Get current user ID on target."""
        logger.debug(f"sys_getuid() on session {self.sid}")
        uid = self._rust.sys_getuid()
        logger.debug(f"sys_getuid() -> {uid}")
        return uid

    def sys_getsid(self) -> str:
        """Get current session ID on target (Windows)."""
        logger.debug(f"sys_getsid() on session {self.sid}")
        return self._rust.sys_getsid()

    def sys_is_system(self) -> bool:
        """Check if running as SYSTEM on target (Windows)."""
        logger.debug(f"sys_is_system() on session {self.sid}")
        result = self._rust.sys_is_system()
        logger.debug(f"sys_is_system() -> {result}")
        return result

    def sys_localtime(self) -> str:
        """Get local time on target."""
        logger.debug(f"sys_localtime() on session {self.sid}")
        return self._rust.sys_localtime()

    def sys_getprivs(self) -> List[str]:
        """Get current privileges on target (Windows)."""
        logger.debug(f"sys_getprivs() on session {self.sid}")
        privs = self._rust.sys_getprivs()
        logger.debug(f"sys_getprivs() -> {len(privs)} privileges")
        return privs

    def sys_sysinfo(self) -> Dict[str, Any]:
        """
        Get system information from target.

        Returns:
            Dictionary with OS, architecture, hostname, domain, etc.
        """
        logger.debug(f"sys_sysinfo() on session {self.sid}")
        info = self._rust.sys_sysinfo()
        logger.debug(f"sys_sysinfo() -> {info.get('Computer', 'unknown')}")
        return info

    def sys_steal_token(self, pid: int) -> bool:
        """
        Steal a process token on target (Windows).

        Args:
            pid: Process ID to steal token from

        Returns:
            True if successful
        """
        logger.info(f"Stealing token from pid {pid} on session {self.sid}")
        try:
            result = self._rust.sys_steal_token(pid)
            if result:
                logger.info(f"Token stolen successfully from pid {pid}")
            else:
                logger.warning(f"Failed to steal token from pid {pid}")
            return result
        except Exception as e:
            logger.error(f"Token theft failed: {e}")
            raise

    def sys_getdrivers(self) -> List[Dict[str, Any]]:
        """Get list of loaded drivers on target (Windows)."""
        logger.debug(f"sys_getdrivers() on session {self.sid}")
        drivers = self._rust.sys_getdrivers()
        logger.debug(f"sys_getdrivers() -> {len(drivers)} drivers")
        return drivers

    def sys_getenv(self, var_name: str) -> Optional[str]:
        """
        Get an environment variable on target.

        Args:
            var_name: Environment variable name

        Returns:
            Variable value, or None if not set
        """
        logger.debug(f"sys_getenv({var_name}) on session {self.sid}")
        return self._rust.sys_getenv(var_name)

    def sys_getenvs(self, var_names: List[str]) -> Dict[str, str]:
        """
        Get multiple environment variables on target.

        Args:
            var_names: List of environment variable names

        Returns:
            Dictionary mapping variable names to values
        """
        logger.debug(f"sys_getenvs({var_names}) on session {self.sid}")
        return self._rust.sys_getenvs(var_names)

    # =========================================================================
    # Meterpreter Network Operations
    # =========================================================================

    def net_get_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interfaces on target."""
        logger.debug(f"net_get_interfaces() on session {self.sid}")
        ifaces = self._rust.net_get_interfaces()
        logger.debug(f"net_get_interfaces() -> {len(ifaces)} interfaces")
        return ifaces

    def net_get_routes(self) -> List[Dict[str, Any]]:
        """Get routing table on target."""
        logger.debug(f"net_get_routes() on session {self.sid}")
        routes = self._rust.net_get_routes()
        logger.debug(f"net_get_routes() -> {len(routes)} routes")
        return routes

    def net_get_arp_table(self) -> List[Dict[str, Any]]:
        """Get ARP table on target."""
        logger.debug(f"net_get_arp_table() on session {self.sid}")
        arp = self._rust.net_get_arp_table()
        logger.debug(f"net_get_arp_table() -> {len(arp)} entries")
        return arp

    def net_get_netstat(self) -> List[Dict[str, Any]]:
        """Get network connections on target."""
        logger.debug(f"net_get_netstat() on session {self.sid}")
        conns = self._rust.net_get_netstat()
        logger.debug(f"net_get_netstat() -> {len(conns)} connections")
        return conns

    def net_get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration on target."""
        logger.debug(f"net_get_proxy_config() on session {self.sid}")
        return self._rust.net_get_proxy_config()

    def net_add_route(self, subnet: str, netmask: str, gateway: str) -> None:
        """
        Add a route on target.

        Args:
            subnet: Destination subnet
            netmask: Subnet mask
            gateway: Gateway address
        """
        logger.info(
            f"Adding route on session {self.sid}: {subnet}/{netmask} via {gateway}"
        )
        self._rust.net_add_route(subnet, netmask, gateway)

    def net_remove_route(self, subnet: str, netmask: str, gateway: str) -> None:
        """
        Remove a route on target.

        Args:
            subnet: Destination subnet
            netmask: Subnet mask
            gateway: Gateway address
        """
        logger.info(
            f"Removing route on session {self.sid}: {subnet}/{netmask} via {gateway}"
        )
        self._rust.net_remove_route(subnet, netmask, gateway)

    # =========================================================================
    # Meterpreter Core Operations
    # =========================================================================

    def meterpreter_shutdown(self) -> bool:
        """Gracefully shutdown the meterpreter session."""
        logger.info(f"Shutting down meterpreter session {self.sid}")
        try:
            result = self._rust.meterpreter_shutdown()
            if result:
                logger.info(f"Meterpreter session {self.sid} shutdown complete")
            else:
                logger.warning(f"Meterpreter session {self.sid} shutdown returned false")
            return result
        except Exception as e:
            logger.error(f"Meterpreter shutdown failed: {e}")
            raise

    def meterpreter_use(self, extension_name: str) -> bool:
        """
        Load a meterpreter extension.

        Args:
            extension_name: Name of extension to load (e.g., "stdapi", "priv")

        Returns:
            True if extension loaded successfully
        """
        logger.debug(f"Loading meterpreter extension: {extension_name}")
        try:
            result = self._rust.meterpreter_use(extension_name)
            if result:
                logger.debug(f"Extension {extension_name} loaded successfully")
            else:
                logger.warning(f"Extension {extension_name} failed to load")
            return result
        except Exception as e:
            logger.error(f"Failed to load extension {extension_name}: {e}")
            raise

    def meterpreter_secure(self) -> bool:
        """Enable encrypted communication for session."""
        logger.debug(f"Enabling secure communication on session {self.sid}")
        return self._rust.meterpreter_secure()

    def meterpreter_machine_id(self, timeout: Optional[int] = None) -> str:
        """
        Get the machine ID of the target.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Machine ID string
        """
        logger.debug(f"meterpreter_machine_id() on session {self.sid}")
        return self._rust.meterpreter_machine_id(timeout)

    def meterpreter_native_arch(self, timeout: Optional[int] = None) -> str:
        """
        Get the native architecture of the target.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Architecture string (e.g., "x64", "x86")
        """
        logger.debug(f"meterpreter_native_arch() on session {self.sid}")
        arch = self._rust.meterpreter_native_arch(timeout)
        logger.debug(f"meterpreter_native_arch() -> {arch}")
        return arch

    def meterpreter_session_guid(self, timeout: Optional[int] = None) -> str:
        """
        Get the session GUID.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            Session GUID string
        """
        logger.debug(f"meterpreter_session_guid() on session {self.sid}")
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
        logger.info(
            f"Migrating session {self.sid} to pid {target_pid} (writable_dir={writable_dir})"
        )
        try:
            result = self._rust.meterpreter_migrate(target_pid, writable_dir, timeout)
            if result:
                logger.info(f"Migration to pid {target_pid} successful")
            else:
                logger.warning(f"Migration to pid {target_pid} failed")
            return result
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise

    # =========================================================================
    # Meterpreter Transport Operations
    # =========================================================================

    def transport_list(self) -> Dict[str, Any]:
        """Get list of configured transports."""
        logger.debug(f"transport_list() on session {self.sid}")
        return self._rust.transport_list()

    def transport_sleep(self, seconds: int) -> bool:
        """
        Sleep the session for specified seconds.

        Args:
            seconds: Number of seconds to sleep

        Returns:
            True if sleep was initiated
        """
        logger.info(f"Session {self.sid} sleeping for {seconds} seconds")
        return self._rust.transport_sleep(seconds)

    def transport_next(self) -> bool:
        """Switch to the next configured transport."""
        logger.info(f"Switching to next transport on session {self.sid}")
        return self._rust.transport_next()

    def transport_prev(self) -> bool:
        """Switch to the previous configured transport."""
        logger.info(f"Switching to previous transport on session {self.sid}")
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
        logger.info(
            f"Adding transport to session {self.sid}: {transport} (lhost={lhost}, lport={lport})"
        )
        try:
            result = self._rust.transport_add(
                transport,
                lport,
                lhost,
                ua,
                comm_timeout,
                session_exp,
                retry_total,
                retry_wait,
            )
            if result:
                logger.info("Transport added successfully")
            else:
                logger.warning("Failed to add transport")
            return result
        except Exception as e:
            logger.error(f"Failed to add transport: {e}")
            raise

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
        logger.info(
            f"Removing transport from session {self.sid}: {transport} (lhost={lhost}, lport={lport})"
        )
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
        logger.info(
            f"Changing transport on session {self.sid} to: {transport} (lhost={lhost}, lport={lport})"
        )
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
        logger.debug(
            f"Setting transport timeouts on session {self.sid}: exp={session_exp}, comm={comm_timeout}, retry={retry_total}/{retry_wait}"
        )
        return self._rust.set_transport_timeouts(
            session_exp, comm_timeout, retry_total, retry_wait
        )

    # =========================================================================
    # Response Timeout Configuration
    # =========================================================================

    def get_response_timeout(self) -> int:
        """Get the response timeout in seconds."""
        logger.debug(f"get_response_timeout() on session {self.sid}")
        return self._rust.get_response_timeout()

    def set_response_timeout(self, timeout_secs: int) -> None:
        """
        Set the response timeout.

        Args:
            timeout_secs: Timeout in seconds
        """
        logger.debug(f"set_response_timeout({timeout_secs}) on session {self.sid}")
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
        logger.info(
            f"Running post module {module_path} on session {self.sid}"
        )
        if options:
            logger.debug(f"Post module options: {options}")

        try:
            result = self._rust.run_post_module(module_path, options)
            if result:
                logger.info(f"Post module {module_path} completed successfully")
            else:
                logger.warning(f"Post module {module_path} returned false")
            return result
        except Exception as e:
            logger.error(f"Post module {module_path} failed: {e}")
            raise

    # =========================================================================
    # Magic Methods
    # =========================================================================

    def __repr__(self) -> str:
        try:
            parts = [f"<Session {self.sid}: {self.session_type} @ {self.host}:{self.port}"]
            if self.via_exploit:
                # Get just the module name from full path
                exploit_name = self.via_exploit.split('/')[-1] if '/' in self.via_exploit else self.via_exploit
                parts.append(f"via={exploit_name}")
            status = "alive" if self.alive else "dead"
            parts.append(f"[{status}]")
            return " ".join(parts) + ">"
        except Exception:
            return f"<Session {self._rust.sid()}>"

    def __str__(self) -> str:
        try:
            return f"Session #{self.sid} ({self.session_type} @ {self.host})"
        except Exception:
            return f"Session #{self._rust.sid()}"

    def summary(self, full: bool = False) -> str:
        """Get a detailed multi-line summary of this session.

        Args:
            full: Reserved for future use (consistency with other classes).

        Returns:
            Formatted string with full session details including
            connection info, exploit/payload used, and status.

        Example:
            >>> print(session.summary())
            >>> session.p()  # Shorthand
        """
        _ = full  # Reserved for future use
        try:
            status = "✓ ALIVE" if self.alive else "✗ DEAD"
            lines = [
                f"{'═' * 60}",
                f"  Session #{self.sid} - {self.session_type.upper()}",
                f"{'═' * 60}",
                f"",
                f"  Status: {status}",
                f"  Target: {self.host}:{self.port}",
            ]

            if self.tunnel_peer:
                lines.append(f"  Tunnel: {self.tunnel_peer}")

            if self.info:
                lines.append(f"  Info: {self.info}")

            lines.append(f"")
            lines.append(f"  Created Via:")
            if self.via_exploit:
                lines.append(f"    Exploit: {self.via_exploit}")
            if self.via_payload:
                lines.append(f"    Payload: {self.via_payload}")

            # Add meterpreter-specific info if available
            if "meterpreter" in self.session_type.lower():
                lines.append(f"")
                lines.append(f"  Meterpreter Info:")
                try:
                    lines.append(f"    PID: {self.process_getpid()}")
                except Exception:
                    pass
                try:
                    lines.append(f"    User: {self.sys_getuid()}")
                except Exception:
                    pass
                try:
                    sysinfo = self.sys_sysinfo()
                    if sysinfo.get("Computer"):
                        lines.append(f"    Computer: {sysinfo.get('Computer')}")
                    if sysinfo.get("OS"):
                        lines.append(f"    OS: {sysinfo.get('OS')}")
                except Exception:
                    pass

            lines.append(f"{'─' * 60}")
            return "\n".join(lines)
        except Exception as e:
            return f"<Session {self._rust.sid()} - error getting details: {e}>"

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: Reserved for future use (consistency with other classes).
        """
        # Gather meterpreter info if available
        meterpreter_info = None
        if "meterpreter" in self.session_type.lower() and self.alive:
            meterpreter_info = {}
            try:
                meterpreter_info["user"] = self._rust.sys_getuid()
            except Exception:
                pass
            try:
                meterpreter_info["pid"] = self._rust.process_getpid()
            except Exception:
                pass
            try:
                sysinfo = self._rust.sys_sysinfo()
                meterpreter_info["computer"] = sysinfo.get("Computer")
                meterpreter_info["os"] = sysinfo.get("OS")
            except Exception:
                pass

        print_session(
            sid=self.sid,
            session_type=self.session_type,
            host=self.host,
            port=self.port,
            alive=self.alive,
            via_exploit=self.via_exploit,
            via_payload=self.via_payload,
            tunnel_peer=self.tunnel_peer,
            info=self.info,
            meterpreter_info=meterpreter_info if meterpreter_info else None,
            full=full,
        )

    def __bool__(self) -> bool:
        """Session is truthy if alive."""
        try:
            return self.alive
        except Exception:
            return False
