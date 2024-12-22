"""Metasploit Python Interface.

This module initializes the core and async Python bindings for Metasploit Core.
"""

from assassinate.async_core import (
    async_msf_close_session,
    async_msf_get_version,
    async_msf_init,
    async_msf_interact_session,
    async_msf_list_jobs,
    async_msf_list_modules,
    async_msf_list_sessions,
    async_msf_module_info,
    async_msf_payload_generator,
    async_msf_run_module,
    async_msf_shutdown,
    async_msf_stop_job,
)
from assassinate.core import (
    msf_close_session,
    msf_get_version,
    msf_init,
    msf_interact_session,
    msf_list_jobs,
    msf_list_modules,
    msf_list_sessions,
    msf_module_info,
    msf_payload_generator,
    msf_run_module,
    msf_shutdown,
    msf_stop_job,
)
from assassinate.exceptions import (
    ExecutionError,
    InitializationError,
    JobError,
    MetasploitError,
    SessionError,
    ValidationError,
)
from assassinate.logger import (
    get_logger,
    set_logger_level,
    setup_logger,
)

__all__ = [
    "msf_init",
    "msf_get_version",
    "msf_list_modules",
    "msf_module_info",
    "msf_run_module",
    "msf_list_sessions",
    "msf_interact_session",
    "msf_close_session",
    "msf_list_jobs",
    "msf_stop_job",
    "msf_payload_generator",
    "msf_shutdown",
    "async_msf_init",
    "async_msf_get_version",
    "async_msf_list_modules",
    "async_msf_module_info",
    "async_msf_run_module",
    "async_msf_list_sessions",
    "async_msf_interact_session",
    "async_msf_close_session",
    "async_msf_list_jobs",
    "async_msf_stop_job",
    "async_msf_payload_generator",
    "async_msf_shutdown",
    "MetasploitError",
    "InitializationError",
    "ValidationError",
    "ExecutionError",
    "SessionError",
    "JobError",
    "setup_logger",
    "get_logger",
    "set_logger_level",
]
