from __future__ import annotations
import asyncio
from core import (
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
    msf_shutdown,
)


async def async_msf_init() -> bool:
    """
    Asynchronously initialize the Metasploit Core library.

    :return: True if initialization is successful, False otherwise.
    :rtype: bool

    :raises InitializationError: If the library fails to initialize.

    .. seealso:: :func:`msf_init`
    """
    return await asyncio.to_thread(msf_init)


async def async_msf_get_version() -> str:
    """
    Asynchronously retrieve the version of Metasploit Core.

    :return: The version string of Metasploit Core.
    :rtype: str

    .. note::
        This function requires the library to be initialized.

    .. seealso:: :func:`msf_get_version`
    """
    return await asyncio.to_thread(msf_get_version)


async def async_msf_list_modules(module_type: str) -> list[str]:
    """
    Asynchronously list available modules of a specific type.

    :param module_type: The type of modules to list (e.g., "exploit", "auxiliary").
    :type module_type: str

    :return: A list of available module names.
    :rtype: list[str]

    :raises ValidationError: If the module type is invalid.

    .. seealso:: :func:`msf_list_modules`
    """
    return await asyncio.to_thread(msf_list_modules, module_type)


async def async_msf_module_info(module_type: str, module_name: str) -> dict:
    """
    Asynchronously get module information.

    :param module_type: The type of the module.
    :type module_type: str
    :param module_name: The name of the module.
    :type module_name: str

    :return: A dictionary containing module details.
    :rtype: dict

    :raises ValidationError: If the module type or name is invalid.

    .. seealso:: :func:`msf_module_info`
    """
    return await asyncio.to_thread(msf_module_info, module_type, module_name)


async def async_msf_run_module(module_type: str, module_name: str, options: dict) -> bool:
    """
    Asynchronously run a module with given options.

    :param module_type: The type of the module.
    :type module_type: str
    :param module_name: The name of the module.
    :type module_name: str
    :param options: A dictionary containing module options.
    :type options: dict

    :return: True if the module executed successfully, False otherwise.
    :rtype: bool

    :raises ExecutionError: If the module fails to run.

    .. seealso:: :func:`msf_run_module`
    """
    return await asyncio.to_thread(msf_run_module, module_type, module_name, options)


async def async_msf_list_sessions() -> list[str]:
    """
    Asynchronously list active sessions.

    :return: A list of active session identifiers.
    :rtype: list[str]

    .. seealso:: :func:`msf_list_sessions`, :func:`async_msf_interact_session`
    """
    return await asyncio.to_thread(msf_list_sessions)


async def async_msf_interact_session(session_id: str) -> bool:
    """
    Asynchronously interact with an active session.

    :param session_id: The ID of the session to interact with.
    :type session_id: str

    :return: True if the interaction succeeded, False otherwise.
    :rtype: bool

    :raises SessionError: If the session interaction fails.

    .. seealso:: :func:`msf_interact_session`, :func:`async_msf_close_session`
    """
    return await asyncio.to_thread(msf_interact_session, session_id)


async def async_msf_close_session(session_id: str) -> bool:
    """
    Asynchronously close an active session.

    :param session_id: The ID of the session to close.
    :type session_id: str

    :return: True if the session was closed successfully, False otherwise.
    :rtype: bool

    :raises SessionError: If closing the session fails.

    .. seealso:: :func:`msf_close_session`, :func:`async_msf_interact_session`
    """
    return await asyncio.to_thread(msf_close_session, session_id)


async def async_msf_list_jobs() -> list[str]:
    """
    Asynchronously list active jobs.

    :return: A list of active job identifiers.
    :rtype: list[str]

    .. seealso:: :func:`msf_list_jobs`, :func:`async_msf_stop_job`
    """
    return await asyncio.to_thread(msf_list_jobs)


async def async_msf_stop_job(job_id: str) -> bool:
    """
    Asynchronously stop a specific job.

    :param job_id: The ID of the job to stop.
    :type job_id: str

    :return: True if the job was stopped successfully, False otherwise.
    :rtype: bool

    :raises JobError: If stopping the job fails.

    .. seealso:: :func:`msf_stop_job`, :func:`async_msf_list_jobs`
    """
    return await asyncio.to_thread(msf_stop_job, job_id)


async def async_msf_payload_generator(options: dict) -> dict:
    """
    Asynchronously generate a payload with given options.

    :param options: A dictionary containing payload options.
    :type options: dict

    :return: A dictionary containing payload details.
    :rtype: dict

    .. seealso:: :func:`msf_payload_generator`
    """
    return await asyncio.to_thread(msf_payload_generator, options)


async def async_msf_shutdown() -> None:
    """
    Asynchronously shutdown the Metasploit Core library.

    .. warning::
        This will clean up resources and disable further library usage.

    .. seealso:: :func:`msf_shutdown`
    """
    await asyncio.to_thread(msf_shutdown)
