"""Hideout module for managing the assassination framework runtime.

The Hideout is where the hitman operates from. It handles:
- Environment verification (delegates to assassinate-setup)
- Daemon lifecycle management
- Framework client initialization

For installation/setup, use: assassinate-setup --install
"""

from __future__ import annotations

from glob import glob
from os import environ
from pathlib import Path
from subprocess import (
    DEVNULL,
    PIPE,
    CalledProcessError,
    Popen,
    TimeoutExpired,
    run,
)
from time import sleep, time
from typing import TYPE_CHECKING

from assassinate.bridge import Framework, get_version, initialize
from assassinate.log_config import get_logger

if TYPE_CHECKING:
    from types import TracebackType

logger = get_logger("hideout")

# Import shared constants from installer
try:
    from setup.installer import (
        PROJECT_ROOT,
        RUST_DIR,
        MSF_CLONE_PATH,
    )
except ImportError:
    # Fallback if setup module not available
    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
    RUST_DIR = PROJECT_ROOT / "rust"
    MSF_CLONE_PATH = Path("/opt/metasploit-framework")

# Known safehouse locations (MSF installation paths)
KNOWN_SAFEHOUSES = [
    Path("/opt/metasploit-framework"),
    Path("/opt/metasploit-framework/embedded/framework"),
    Path("/usr/share/metasploit-framework"),
]


class Hideout:
    """The Hideout - operational headquarters for assassination missions.

    Manages the runtime environment including daemon lifecycle and
    Framework client connections.

    Note:
        For installation, use: assassinate-setup --install
        Hideout assumes the environment is already set up.

    Attributes:
        framework: Connected Framework client instance
        version: Framework version string
        daemon_process: Running daemon process handle
        safehouse: Path to MSF installation
        ruby_cmd: Path to Ruby executable
        bundle_cmd: Path to Bundler executable
        ruby_env: Environment variables for Ruby execution
    """

    __slots__ = (
        "framework",
        "version",
        "daemon_process",
        "safehouse",
        "ruby_cmd",
        "bundle_cmd",
        "ruby_env",
        "_omnibus_root",
    )

    def __init__(self, skip_verify: bool = False):
        """Initialize the Hideout.

        Args:
            skip_verify: Skip environment verification (not recommended)

        Raises:
            RuntimeError: If environment not ready or initialization fails
        """
        logger.debug("Establishing hideout...")
        self.daemon_process: Popen[bytes] | None = None
        self.framework: Framework | None = None
        self.version: str | None = None

        # Discover environment paths
        self.safehouse = self._locate_safehouse()
        self._omnibus_root: Path | None = None
        self.ruby_cmd, self.bundle_cmd, self.ruby_env = (
            self._identify_ruby_environment()
        )

        logger.debug(f"Safehouse: {self.safehouse}")

        # Verify environment is ready (delegates to setup)
        if not skip_verify:
            self._verify_environment()

        try:
            # Start daemon if not already running
            if not self._is_daemon_active():
                self._deploy_daemon()
            else:
                logger.info("Daemon already active")

            # Initialize Framework client
            initialize()
            self.framework = Framework()
            self.version = get_version()
            logger.info(
                f"Hideout established successfully, version={self.version}"
            )
        except RuntimeError:
            logger.error("Failed to establish hideout")
            self.cleanup()
            raise
        except (OSError, IOError) as e:
            logger.error(f"IO error during hideout setup: {e}")
            self.cleanup()
            raise RuntimeError(f"Failed to establish hideout: {e}") from e
        except (CalledProcessError, TimeoutExpired) as e:
            logger.error(f"Process error during hideout setup: {e}")
            self.cleanup()
            raise RuntimeError(f"Failed to establish hideout: {e}") from e

    def __del__(self) -> None:
        self.cleanup()

    def __enter__(self) -> Hideout:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        self.cleanup()
        return False

    def cleanup(self) -> None:
        """Clean up all resources and evacuate the hideout."""
        logger.debug("Evacuating hideout...")
        self._recall_daemon()
        try:
            run(["rm", "-f", "/dev/shm/assassinate_msf_ipc*"], stderr=DEVNULL)
            logger.debug("Cleared dead drops (shared memory)")
        except (OSError, FileNotFoundError) as e:
            logger.warning(f"Failed to clear dead drops: {e}")

    def verify_environment(self) -> None:
        """Verify environment is ready via assassinate-setup.

        Raises:
            RuntimeError: If environment verification fails.
        """
        self._verify_environment()

    # =========================================================================
    # Daemon Lifecycle
    # =========================================================================

    def _is_daemon_active(self) -> bool:
        """Check if daemon is active via shared memory files."""
        try:
            return len(glob("/dev/shm/assassinate_msf_ipc*")) > 0
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot check daemon status: {e}")
            return False

    def _deploy_daemon(
        self, log_level: str = "info", timeout: int = 15
    ) -> None:
        """Deploy the daemon operative."""
        logger.info("Deploying daemon operative...")

        # Locate daemon binary
        cargo_target_dir = environ.get("CARGO_TARGET_DIR")
        if cargo_target_dir:
            daemon_path = Path(cargo_target_dir) / "release" / "daemon"
        else:
            daemon_path = RUST_DIR / "daemon" / "target" / "release" / "daemon"

        if not daemon_path.exists():
            logger.error(f"Daemon binary not found: {daemon_path}")
            raise RuntimeError(
                f"Daemon not found at {daemon_path}. "
                "Run: assassinate-setup --install"
            )

        # Clean up any previous operations
        logger.debug("Cleaning up previous operations...")
        try:
            run(["pkill", "-f", "daemon.*msf-root"], stderr=DEVNULL)
        except (OSError, FileNotFoundError):
            pass
        sleep(0.5)

        try:
            run(["rm", "-f", "/dev/shm/assassinate_msf_ipc*"], stderr=DEVNULL)
        except (OSError, FileNotFoundError):
            pass

        # Build environment
        env = self.ruby_env.copy()
        if "ASSASSINATE_WORKSPACE" not in env:
            env["ASSASSINATE_WORKSPACE"] = "default"

        # Deploy
        logger.debug(f"Deploying: {daemon_path} --log-level {log_level}")
        try:
            self.daemon_process = Popen(
                [
                    str(daemon_path),
                    "--msf-root",
                    str(self.safehouse),
                    "--log-level",
                    log_level,
                ],
                stdout=PIPE,
                stderr=PIPE,
                env=env,
            )
            logger.debug(f"Daemon deployed, pid={self.daemon_process.pid}")
        except FileNotFoundError:
            logger.error(f"Daemon not found: {daemon_path}")
            raise RuntimeError(
                f"Daemon not found: {daemon_path}. "
                "Run: assassinate-setup --install"
            )
        except PermissionError:
            logger.error(f"Permission denied: {daemon_path}")
            raise RuntimeError(f"Permission denied: {daemon_path}")
        except OSError as e:
            logger.error(f"Failed to deploy daemon: {e}")
            raise RuntimeError(f"Failed to deploy daemon: {e}")

        # Wait for daemon to become active
        logger.debug(f"Waiting for daemon (timeout={timeout}s)...")
        start = time()
        while time() - start < timeout:
            if self.daemon_process.poll() is not None:
                logger.debug("Daemon exited prematurely")
                break
            if self._is_daemon_active():
                logger.info("Daemon operative deployed successfully")
                return
            sleep(0.5)

        # Daemon failed
        logger.error("Daemon failed to deploy")
        stdout_data, stderr_data = b"", b""
        if self.daemon_process and self.daemon_process.poll() is not None:
            try:
                stdout_data, stderr_data = self.daemon_process.communicate(
                    timeout=5
                )
            except TimeoutExpired:
                logger.warning("Timeout reading daemon output")
                self.daemon_process.kill()
                stdout_data, stderr_data = self.daemon_process.communicate()
            except (OSError, ValueError) as e:
                logger.warning(f"Error reading daemon output: {e}")

        self._recall_daemon()
        try:
            run(["rm", "-f", "/dev/shm/assassinate_msf_ipc*"], stderr=DEVNULL)
        except (OSError, FileNotFoundError):
            pass

        raise RuntimeError(
            f"Daemon failed to deploy:\n"
            f"STDOUT: {stdout_data.decode()}\n"
            f"STDERR: {stderr_data.decode()}"
        )

    def _recall_daemon(self) -> None:
        """Recall (stop) the daemon operative."""
        proc = getattr(self, "daemon_process", None)
        if not proc:
            return

        logger.debug(f"Recalling daemon, pid={proc.pid}")

        # Graceful termination
        try:
            proc.terminate()
            logger.debug("Sent recall signal (SIGTERM)")
        except OSError as e:
            logger.warning(f"Error recalling daemon: {e}")
            self.daemon_process = None
            return

        # Wait for termination
        try:
            proc.wait(timeout=5)
            logger.debug("Daemon recalled gracefully")
        except TimeoutExpired:
            logger.warning("Daemon not responding, forcing recall (SIGKILL)")
            try:
                proc.kill()
            except OSError as e:
                logger.warning(f"Error forcing recall: {e}")

            try:
                proc.wait(timeout=2)
                logger.debug("Daemon forcefully recalled")
            except TimeoutExpired:
                logger.error("Daemon did not respond to SIGKILL")
            except OSError as e:
                logger.warning(f"Error waiting for daemon: {e}")
        except OSError as e:
            logger.warning(f"Error waiting for daemon: {e}")

        self.daemon_process = None
        logger.info("Daemon operative recalled")

    # =========================================================================
    # Environment Verification
    # =========================================================================

    def _verify_environment(self) -> None:
        """Verify environment using assassinate-setup --verify.

        Raises:
            RuntimeError: If verification fails.
        """
        logger.info("Verifying environment...")
        try:
            result = run(
                ["assassinate-setup", "--verify"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.error("Environment verification failed")
                raise RuntimeError(
                    "Environment not ready. Run: assassinate-setup --install\n"
                    f"{result.stdout}"
                )
            logger.debug("Environment verified successfully")
        except FileNotFoundError:
            # assassinate-setup not in PATH, do quick local check
            logger.debug("assassinate-setup not in PATH, doing quick check")
            self._quick_verify()
        except TimeoutExpired:
            logger.error("Environment verification timed out")
            raise RuntimeError("Environment verification timed out")

    def _quick_verify(self) -> None:
        """Quick local verification when assassinate-setup not available."""
        # Check daemon exists
        cargo_target_dir = environ.get("CARGO_TARGET_DIR")
        if cargo_target_dir:
            daemon_path = Path(cargo_target_dir) / "release" / "daemon"
        else:
            daemon_path = RUST_DIR / "daemon" / "target" / "release" / "daemon"

        if not daemon_path.exists():
            raise RuntimeError(
                f"Daemon not built at {daemon_path}. "
                "Run: assassinate-setup --install"
            )

        # Check MSF exists
        if not self.safehouse.exists():
            raise RuntimeError(
                f"MSF not found at {self.safehouse}. "
                "Run: assassinate-setup --install"
            )

        logger.debug("Quick verification passed")

    # =========================================================================
    # Path Discovery
    # =========================================================================

    def _locate_safehouse(self) -> Path:
        """Locate the MSF safehouse (installation directory).

        Checks in order:
        1. MSF_ROOT environment variable
        2. Project-local metasploit-framework directory
        3. Known system installation paths
        """
        # Check environment variable
        msf_root_env = environ.get("MSF_ROOT")
        if msf_root_env:
            path = Path(msf_root_env)
            logger.debug(f"Safehouse from MSF_ROOT: {path}")
            return path

        # Check project-local directory
        local_msf = PROJECT_ROOT / "metasploit-framework"
        if local_msf.exists() and (local_msf / "Gemfile").exists():
            logger.debug(f"Safehouse (local): {local_msf}")
            return local_msf

        # Scan known locations
        for path in KNOWN_SAFEHOUSES:
            if path.exists() and (path / "Gemfile").exists():
                logger.debug(f"Safehouse (detected): {path}")
                return path

        # Fall back to standard clone path
        logger.debug(f"Safehouse (fallback): {MSF_CLONE_PATH}")
        return MSF_CLONE_PATH

    def _find_omnibus_root(self) -> Path | None:
        """Find omnibus installation root if applicable."""
        if self._omnibus_root is not None:
            return self._omnibus_root

        try:
            msf_path = self.safehouse.resolve()
            # Check if inside embedded/framework
            if len(msf_path.parts) >= 2 and msf_path.parts[-2:] == (
                "embedded",
                "framework",
            ):
                omnibus_root = msf_path.parent.parent
                if (omnibus_root / "embedded" / "bin" / "ruby").exists():
                    self._omnibus_root = omnibus_root
                    return omnibus_root

            # Check common omnibus path
            omnibus_path = Path("/opt/metasploit-framework")
            if (omnibus_path / "embedded" / "bin" / "ruby").exists():
                self._omnibus_root = omnibus_path
                return omnibus_path
        except (OSError, PermissionError):
            pass

        return None

    def _identify_ruby_environment(self) -> tuple[str, str, dict[str, str]]:
        """Identify Ruby environment for daemon operations.

        Checks in order:
        1. Omnibus embedded Ruby
        2. rbenv Ruby
        3. System Ruby
        """
        ruby_cmd = "ruby"
        bundle_cmd = "bundle"
        env = environ.copy()

        # Check for omnibus Ruby
        omnibus_root = self._find_omnibus_root()
        if omnibus_root:
            embedded_bin = omnibus_root / "embedded" / "bin"
            omnibus_ruby = embedded_bin / "ruby"
            omnibus_bundle = embedded_bin / "bundle"
            if omnibus_ruby.exists():
                ruby_cmd = str(omnibus_ruby)
                bundle_cmd = (
                    str(omnibus_bundle) if omnibus_bundle.exists() else "bundle"
                )
                # Set library path for omnibus
                embedded_lib = omnibus_root / "embedded" / "lib"
                if embedded_lib.exists():
                    existing = env.get("LD_LIBRARY_PATH", "")
                    env["LD_LIBRARY_PATH"] = (
                        f"{embedded_lib}:{existing}"
                        if existing
                        else str(embedded_lib)
                    )
                logger.debug(f"Using omnibus Ruby: {ruby_cmd}")
                return (ruby_cmd, bundle_cmd, env)

        # Check for rbenv Ruby
        ruby_version_file = PROJECT_ROOT / ".ruby-version"
        rbenv_root = Path.home() / ".rbenv"

        if ruby_version_file.exists() and rbenv_root.exists():
            try:
                ruby_version = ruby_version_file.read_text().strip()
                rbenv_bin = rbenv_root / "versions" / ruby_version / "bin"
                if rbenv_bin.exists():
                    ruby_cmd = str(rbenv_bin / "ruby")
                    bundle_cmd = str(rbenv_bin / "bundle")
                    logger.debug(f"Using rbenv Ruby {ruby_version}")
                    return (ruby_cmd, bundle_cmd, env)
            except (IOError, OSError) as e:
                logger.warning(f"Cannot read .ruby-version: {e}")

        logger.debug("Using system Ruby")
        return (ruby_cmd, bundle_cmd, env)
