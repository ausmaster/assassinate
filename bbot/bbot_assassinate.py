"""
BBOTAssassinate module provides an API for interacting with the Metasploit Core
shared library.
It supports synchronous and asynchronous operations, allowing users to manage
modules, sessions,
jobs, and payloads. The functionality is designed to streamline interaction with
Metasploit
through a well-defined Python interface.
"""

from __future__ import annotations

from assassinate.core import (
    msf_init,
    msf_get_version,
    msf_list_modules,
    msf_module_info,
    msf_run_module,
    msf_list_sessions,
    msf_interact_session,
    msf_close_session,
    msf_list_jobs,
    msf_stop_job,
    msf_payload_generator,
    msf_shutdown
)
from assassinate.exceptions import InitializationError, ValidationError
from assassinate.logger import setup_logger
from assassinate.utils import validate_json_structure

logger = setup_logger("BBOTAssassinate")

class BBOTAssassinate:
    """
    BBOTAssassinate API provides both synchronous and asynchronous interaction
    with the Metasploit Core shared library.
    """
    def __init__(self) -> None:
        """
        Initialize both synchronous and asynchronous APIs.
        """
        try:
            if not msf_init():
                raise InitializationError("Failed to initialize Metasploit Core library.")
            logger.info("Successfully initialized BBOTAssassinate interface.")
        except InitializationError as e:
            logger.error(f"Initialization failed: {e}")
            raise

    def get_version(self) -> str:
        """
        Retrieve the Metasploit version.
        :return: Version string.
        """
        version = msf_get_version()
        logger.info(f"Metasploit version: {version}")
        return version

    def list_modules(self, module_type: str) -> list:
        """
        List available modules.
        :param module_type: Module type (e.g., 'exploit', 'payload').
        :return: List of modules.
        """
        modules = msf_list_modules(module_type)
        logger.info(f"Retrieved {len(modules)} modules of type '{module_type}'.")
        return modules

    def module_info(self, module_type: str, module_name: str) -> dict:
        """
        Retrieve module information.
        :param module_type: Module type.
        :param module_name: Module name.
        :return: Module details as a dictionary.
        """
        info = msf_module_info(module_type, module_name)
        logger.info(f"Retrieved module info for '{module_name}'.")
        return info

    def run_module(self, module_type: str, module_name: str, options: dict) -> bool:
        """
        Run a module with given options.
        :param module_type: Module type.
        :param module_name: Module name.
        :param options: Module options.
        :return: True if execution is successful.
        """
        schema = {"module_type": str, "module_name": str, "options": dict}
        if not validate_json_structure({"module_type": module_type, "module_name": module_name, "options": options}, schema):
            raise ValidationError("Invalid module configuration.")
        result = msf_run_module(module_type, module_name, options)
        logger.info(f"Module '{module_name}' executed successfully.")
        return result

    def list_sessions(self) -> list:
        """
        List active sessions.
        :return: List of active session identifiers.
        """
        sessions = msf_list_sessions()
        logger.info(f"Retrieved {len(sessions)} active sessions.")
        return sessions

    def interact_session(self, session_id: str) -> bool:
        """
        Interact with an active session.
        :param session_id: The ID of the session to interact with.
        :return: True if interaction is successful.
        """
        result = msf_interact_session(session_id)
        logger.info(f"Interacted with session '{session_id}'.")
        return result

    def close_session(self, session_id: str) -> bool:
        """
        Close an active session.
        :param session_id: The ID of the session to close.
        :return: True if the session was closed successfully.
        """
        result = msf_close_session(session_id)
        logger.info(f"Closed session '{session_id}'.")
        return result

    def list_jobs(self) -> list:
        """
        List active jobs.
        :return: List of active job identifiers.
        """
        jobs = msf_list_jobs()
        logger.info(f"Retrieved {len(jobs)} active jobs.")
        return jobs

    def stop_job(self, job_id: str) -> bool:
        """
        Stop a specific job.
        :param job_id: The ID of the job to stop.
        :return: True if the job was stopped successfully.
        """
        result = msf_stop_job(job_id)
        logger.info(f"Stopped job '{job_id}'.")
        return result

    def payload_generator(self, options: dict) -> dict:
        """
        Generate a payload with given options.
        :param options: Dictionary containing payload options.
        :return: Dictionary containing payload details.
        """
        payload = msf_payload_generator(options)
        logger.info(f"Generated payload with options: {options}.")
        return payload

    def shutdown(self) -> None:
        """
        Shutdown the Metasploit Core library.
        """
        msf_shutdown()
        logger.info("Metasploit Core library shutdown successfully.")

__all__ = ["BBOTAssassinate"]
