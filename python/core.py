from __future__ import annotations
from ctypes import cdll, c_char_p, c_bool

# Load the shared library
lib = cdll.LoadLibrary("./libmetasploit_core.so")


def msf_init() -> bool:
    """
    Initialize the Metasploit Core library.

    :return: True if initialization is successful, False otherwise.
    :rtype: bool

    :raises InitializationError: If the library fails to initialize.

    .. seealso:: :func:`msf_shutdown`
    """
    result = lib.rb_msf_init()
    return bool(result)


def msf_get_version() -> str:
    """
    Retrieve the version of Metasploit Core.

    :return: The version string of Metasploit Core.
    :rtype: str

    .. note::
        This function requires the library to be initialized.

    .. seealso:: :func:`msf_init`
    """
    lib.rb_msf_get_version.restype = c_char_p
    return lib.rb_msf_get_version().decode("utf-8")


def msf_list_modules(module_type: str) -> list[str]:
    """
    List available modules of a specific type.

    :param module_type: The type of modules to list (e.g., "exploit", "auxiliary").
    :type module_type: str

    :return: A list of available module names.
    :rtype: list[str]

    :raises ValidationError: If the module type is invalid.

    .. seealso:: :func:`msf_module_info`
    """
    lib.rb_msf_list_modules.restype = c_char_p
    return lib.rb_msf_list_modules(module_type.encode("utf-8")).decode("utf-8").split(",")


def msf_module_info(module_type: str, module_name: str) -> dict:
    """
    Get module information.

    :param module_type: The type of the module.
    :type module_type: str
    :param module_name: The name of the module.
    :type module_name: str

    :return: A dictionary containing module details.
    :rtype: dict

    :raises ValidationError: If the module type or name is invalid.

    .. seealso:: :func:`msf_list_modules`
    """
    lib.rb_msf_module_info.restype = c_char_p
    info = lib.rb_msf_module_info(
        module_type.encode("utf-8"), module_name.encode("utf-8")
    ).decode("utf-8")
    return eval(info)  # Assuming JSON-like string


def msf_run_module(module_type: str, module_name: str, options: dict) -> bool:
    """
    Run a module with given options.

    :param module_type: The type of the module.
    :type module_type: str
    :param module_name: The name of the module.
    :type module_name: str
    :param options: A dictionary containing module options.
    :type options: dict

    :return: True if the module executed successfully, False otherwise.
    :rtype: bool

    :raises ExecutionError: If the module fails to run.

    .. seealso:: :func:`msf_module_info`
    """
    lib.rb_msf_run_module.restype = c_bool
    return bool(
        lib.rb_msf_run_module(
            module_type.encode("utf-8"), module_name.encode("utf-8"), options
        )
    )


def msf_list_sessions() -> list[str]:
    """
    List active sessions.

    :return: A list of active session identifiers.
    :rtype: list[str]

    .. seealso:: :func:`msf_interact_session`, :func:`msf_close_session`
    """
    lib.rb_msf_list_sessions.restype = c_char_p
    return lib.rb_msf_list_sessions().decode("utf-8").split(",")


def msf_interact_session(session_id: str) -> bool:
    """
    Interact with an active session.

    :param session_id: The ID of the session to interact with.
    :type session_id: str

    :return: True if the interaction succeeded, False otherwise.
    :rtype: bool

    :raises SessionError: If the session interaction fails.

    .. seealso:: :func:`msf_close_session`
    """
    lib.rb_msf_interact_session.restype = c_bool
    return bool(lib.rb_msf_interact_session(session_id.encode("utf-8")))


def msf_close_session(session_id: str) -> bool:
    """
    Close an active session.

    :param session_id: The ID of the session to close.
    :type session_id: str

    :return: True if the session was closed successfully, False otherwise.
    :rtype: bool

    :raises SessionError: If closing the session fails.

    .. seealso:: :func:`msf_interact_session`
    """
    lib.rb_msf_close_session.restype = c_bool
    return bool(lib.rb_msf_close_session(session_id.encode("utf-8")))


def msf_list_jobs() -> list[str]:
    """
    List active jobs.

    :return: A list of active job identifiers.
    :rtype: list[str]

    .. seealso:: :func:`msf_stop_job`
    """
    lib.rb_msf_list_jobs.restype = c_char_p
    return lib.rb_msf_list_jobs().decode("utf-8").split(",")


def msf_stop_job(job_id: str) -> bool:
    """
    Stop a specific job.

    :param job_id: The ID of the job to stop.
    :type job_id: str

    :return: True if the job was stopped successfully, False otherwise.
    :rtype: bool

    :raises JobError: If stopping the job fails.

    .. seealso:: :func:`msf_list_jobs`
    """
    lib.rb_msf_stop_job.restype = c_bool
    return bool(lib.rb_msf_stop_job(job_id.encode("utf-8")))


def msf_payload_generator(options: dict) -> dict:
    """
    Generate a payload with given options.

    :param options: A dictionary containing payload options.
    :type options: dict

    :return: A dictionary containing payload details.
    :rtype: dict

    :raises ValidationError: If the payload options are invalid.

    :Example:

        >>> from core import msf_payload_generator
        >>> payload = msf_payload_generator({"option1": "value1"})
        >>> print(payload)

    .. seealso:: :func:`msf_run_module`
    """
    lib.rb_msf_payload_generator.restype = c_char_p
    payload = lib.rb_msf_payload_generator(options).decode("utf-8")
    return eval(payload)  # Assuming JSON-like string



def msf_shutdown() -> None:
    """
    Shutdown the Metasploit Core library.

    .. warning::
        This will clean up resources and disable further library usage.

    .. seealso:: :func:`msf_init`
    """
    lib.rb_msf_shutdown()
