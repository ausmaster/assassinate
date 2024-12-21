"""Custom exceptions for Metasploit Core Python bindings.

This module defines exception classes for error handling in Metasploit Python bindings,
covering initialization, validation, and runtime errors.
"""

from __future__ import annotations


class MetasploitError(Exception):
    """Base exception for all Metasploit-related errors.

    All custom exceptions in this module inherit from this base class.

    .. note::
        This exception is not meant to be raised directly. Use specific
        subclasses instead.

    .. seealso:: :class:`InitializationError`, :class:`ValidationError`,
    :class:`ExecutionError`
    """


class InitializationError(MetasploitError):
    """Exception raised when Metasploit Core initialization fails.

    This can occur if the shared library cannot be loaded, or initialization
    steps fail.

    Example:
        >>> from core import msf_init
        >>> if not msf_init():
        >>>     raise InitializationError("Failed to initialize Metasploit
        Core library.")

    .. seealso:: :func:`core.msf_init`

    """


class ValidationError(MetasploitError):
    """Exception raised for invalid parameters or configurations.

    This occurs when an API call receives invalid arguments or malformed
    options.

    Example:
        >>> from core import msf_list_modules
        >>> msf_list_modules(123)  # Raises ValidationError

    .. seealso:: :func:`core.msf_list_modules`, :func:`core.msf_module_info`

    """


class ExecutionError(MetasploitError):
    """Exception raised when a module execution fails.

    This happens if a module cannot run due to internal errors or missing
    dependencies.

    Example:
        >>> from core import msf_run_module
        >>> if not msf_run_module("exploit", "example_module", {}):
        >>>     raise ExecutionError("Failed to run the module.")

    .. seealso:: :func:`core.msf_run_module`

    """


class SessionError(MetasploitError):
    """Exception raised for session-related errors.

    Examples include failure to interact with or close an active session.

    Example:
        >>> from core import msf_interact_session
        >>> if not msf_interact_session("session1"):
        >>>     raise SessionError("Failed to interact with session.")

    .. seealso:: :func:`core.msf_interact_session`,
    :func:`core.msf_close_session`

    """


class JobError(MetasploitError):
    """Exception raised for job-related errors.

    This can happen if a job cannot be stopped or fails during execution.

    Example:
        >>> from core import msf_stop_job
        >>> if not msf_stop_job("job1"):
        >>>     raise JobError("Failed to stop the job.")

    .. seealso:: :func:`core.msf_list_jobs`, :func:`core.msf_stop_job`

    """
