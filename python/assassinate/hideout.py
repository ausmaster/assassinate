"""Hideout module for managing the assassination framework runtime.

The Hideout is where the hitman prepares for missions. It handles:
- Environment setup (Rust compilation, Ruby/gem installation)
- Daemon lifecycle management
- Framework client initialization
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

from assassinate.assassinate.prep import HideoutPrep, PrepReport
from assassinate.bridge import Framework, get_version, initialize
from assassinate.log_config import get_logger

if TYPE_CHECKING:
    from types import TracebackType

logger = get_logger("hideout")


class Hideout:
    """The Hideout - operational headquarters for assassination missions.

    Manages the runtime environment including Rust daemon, Ruby/MSF setup,
    and Framework client connections.

    Attributes:
        framework: Connected Framework client instance
        version: Framework version string
        prep: Hideout preparation handler for environment checks
        daemon_process: Running daemon process handle
    """

    __slots__ = (
        "framework",
        "version",
        "prep",
        "daemon_process",
    )

    def __init__(self, skip_prep: bool = False):
        """Initialize the Hideout.

        Args:
            skip_prep: Skip preparation checks (not recommended)

        Raises:
            RuntimeError: If prep fails or initialization fails
        """
        logger.debug("Establishing hideout...")
        self.daemon_process: Popen[bytes] | None = None
        self.framework: Framework | None = None
        self.version: str | None = None

        # Perform preparation checks
        self.prep = HideoutPrep()
        logger.debug(f"Project root: {self.prep.project_root}")
        logger.debug(f"Safehouse: {self.prep.safehouse}")

        if not skip_prep:
            report = self.prep.check()
            if not report.ready:
                logger.error("Hideout preparation failed")
                logger.error(report.summary())
                raise RuntimeError(f"Hideout not ready:\n{report.summary()}")

        try:
            self._prepare_arsenal()
            self._establish_safehouse()

            if not self._is_daemon_active():
                self._deploy_daemon()
            else:
                logger.info("Daemon already active")

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

    def check_prep(self) -> PrepReport:
        """Run hideout preparation checks.

        Returns:
            PrepReport with status of all requirements.
        """
        return self.prep.check()

    def _is_daemon_active(self) -> bool:
        """Check if daemon is active via shared memory files."""
        try:
            return len(glob("/dev/shm/assassinate_msf_ipc*")) > 0
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot check daemon status: {e}")
            return False

    def _prepare_arsenal(self) -> None:
        """Compile Rust arsenal if needed."""
        logger.info("Preparing arsenal (Rust compilation)...")

        for weapon, check_ready in self.prep.arsenal.items():
            weapon_path = self.prep.rust_dir / weapon
            release_dir = weapon_path / "target" / "release"

            try:
                if release_dir.exists() and check_ready(release_dir):
                    logger.debug(f"Weapon {weapon} already forged")
                    continue
            except (OSError, PermissionError) as e:
                logger.error(f"Cannot check arsenal for {weapon}: {e}")
                raise RuntimeError(f"Cannot check arsenal: {e}")

            logger.info(f"Forging {weapon}...")
            try:
                run(
                    ["cargo", "build", "--release"],
                    cwd=weapon_path,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=300,
                )
                logger.info(f"Successfully forged {weapon}")
            except TimeoutExpired:
                logger.error(f"Forging {weapon} timed out")
                raise RuntimeError(f"Forging {weapon} timed out")
            except CalledProcessError as e:
                logger.error(f"Failed to forge {weapon}: {e.stderr}")
                raise RuntimeError(f"Failed to forge {weapon}")
            except FileNotFoundError:
                logger.error("Cargo not found")
                raise RuntimeError("Cargo not found - install from rustup.rs")

            if not check_ready(release_dir):
                logger.error(f"Weapon {weapon} not found after forging")
                raise RuntimeError(f"Forging {weapon} produced no artifacts")

        logger.info("Arsenal ready")

    def _establish_safehouse(self) -> None:
        """Set up MSF safehouse (Ruby environment and gems)."""
        logger.info("Establishing safehouse (Ruby/MSF setup)...")

        if not self.prep.safehouse.exists():
            logger.error(f"Safehouse not found: {self.prep.safehouse}")
            raise RuntimeError(f"Safehouse not found: {self.prep.safehouse}")

        # Verify Ruby
        try:
            result = run(
                [self.prep.ruby_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.prep.ruby_env,
            )
            logger.debug(f"Ruby: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("Ruby not found")
            raise RuntimeError("Ruby not found")
        except CalledProcessError as e:
            logger.error(f"Ruby check failed: {e}")
            raise RuntimeError("Ruby check failed")

        # Verify Bundler
        try:
            result = run(
                [self.prep.bundle_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.prep.ruby_env,
            )
            logger.debug(f"Bundler: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("Bundler not found")
            raise RuntimeError("Bundler not found - gem install bundler")
        except CalledProcessError as e:
            logger.error(f"Bundler check failed: {e}")
            raise RuntimeError("Bundler check failed")

        # Check if gems are installed
        gemfile_lock = self.prep.safehouse / "Gemfile.lock"
        bundle_dir = self.prep.safehouse / ".bundle"

        if gemfile_lock.exists() and bundle_dir.exists():
            logger.debug("Checking safehouse supplies...")
            try:
                result = run(
                    [self.prep.bundle_cmd, "check"],
                    cwd=self.prep.safehouse,
                    capture_output=True,
                    text=True,
                    env=self.prep.ruby_env,
                )
                if result.returncode == 0:
                    logger.debug("Safehouse fully stocked")
                    logger.info("Safehouse established")
                    return
                else:
                    logger.debug("Safehouse needs resupply")
            except (OSError, FileNotFoundError) as e:
                logger.debug(f"Supply check error: {e}")

        # Install gems
        logger.info("Resupplying safehouse (bundle install)...")
        try:
            result = run(
                [self.prep.bundle_cmd, "install"],
                cwd=self.prep.safehouse,
                capture_output=True,
                text=True,
                check=True,
                timeout=600,
                env=self.prep.ruby_env,
            )
            logger.info("Safehouse resupplied successfully")
        except TimeoutExpired:
            logger.error("Resupply timed out")
            raise RuntimeError(
                f"Resupply timed out. Manual: cd {self.prep.safehouse} "
                "&& bundle install"
            )
        except CalledProcessError as e:
            logger.error(f"Resupply failed: {e.stderr}")
            raise RuntimeError(
                f"Resupply failed. Manual: cd {self.prep.safehouse} "
                f"&& bundle install\nError: {e.stderr[-500:]}"
            )

        logger.info("Safehouse established")

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
            daemon_path = (
                self.prep.rust_dir / "daemon" / "target" / "release" / "daemon"
            )

        if not daemon_path.exists():
            logger.error(f"Daemon binary not found: {daemon_path}")
            raise RuntimeError(f"Daemon binary not found: {daemon_path}")

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
        env = self.prep.ruby_env.copy()
        if "ASSASSINATE_WORKSPACE" not in env:
            env["ASSASSINATE_WORKSPACE"] = "default"

        # Deploy
        logger.debug(f"Deploying: {daemon_path} --log-level {log_level}")
        try:
            self.daemon_process = Popen(
                [
                    str(daemon_path),
                    "--msf-root",
                    str(self.prep.safehouse),
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
            raise RuntimeError(f"Daemon not found: {daemon_path}")
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
