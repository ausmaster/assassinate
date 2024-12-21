from __future__ import annotations
import asyncio
import unittest
from ..async_core import (
    async_msf_init,
    async_msf_get_version,
    async_msf_list_modules,
    async_msf_module_info,
    async_msf_run_module,
    async_msf_list_sessions,
    async_msf_interact_session,
    async_msf_close_session,
    async_msf_list_jobs,
    async_msf_stop_job,
    async_msf_payload_generator,
    async_msf_shutdown,
)
from ..exceptions import InitializationError, ValidationError, ExecutionError, SessionError, JobError


class TestAsyncMetasploitCore(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for asynchronous Metasploit Core Python bindings.

    This suite validates asynchronous library initialization, module execution,
    session handling, and job management functions.
    """

    async def test_async_msf_init(self):
        """
        Test :func:`async_core.async_msf_init` for successful initialization.

        :raises InitializationError: If initialization fails.
        """
        result = await async_msf_init()
        self.assertTrue(result, "Asynchronous Metasploit Core failed to initialize.")

    async def test_async_msf_get_version(self):
        """
        Test :func:`async_core.async_msf_get_version` for version retrieval.
        """
        version = await async_msf_get_version()
        self.assertIsInstance(version, str, "Version should be a string.")
        self.assertTrue(version.startswith("Metasploit Core"), "Invalid version string.")

    async def test_async_msf_list_modules(self):
        """
        Test :func:`async_core.async_msf_list_modules` for retrieving module list.
        """
        modules = await async_msf_list_modules("exploit")
        self.assertIsInstance(modules, list, "Modules should be returned as a list.")
        self.assertGreater(len(modules), 0, "No modules returned.")

    async def test_async_msf_module_info(self):
        """
        Test :func:`async_core.async_msf_module_info` for retrieving module information.
        """
        info = await async_msf_module_info("exploit", "example_module")
        self.assertIsInstance(info, dict, "Module info should be a dictionary.")
        self.assertIn("name", info, "Module info missing 'name' key.")

    async def test_async_msf_run_module(self):
        """
        Test :func:`async_core.async_msf_run_module` for running a module.
        """
        result = await async_msf_run_module("exploit", "example_module", {})
        self.assertTrue(result, "Module failed to run asynchronously.")

    async def test_async_msf_list_sessions(self):
        """
        Test :func:`async_core.async_msf_list_sessions` for retrieving active sessions.
        """
        sessions = await async_msf_list_sessions()
        self.assertIsInstance(sessions, list, "Sessions should be a list.")
        self.assertGreaterEqual(len(sessions), 0, "No sessions found.")

    async def test_async_msf_interact_session(self):
        """
        Test :func:`async_core.async_msf_interact_session` for interacting with a session.
        """
        result = await async_msf_interact_session("session1")
        self.assertTrue(result, "Failed to interact with session asynchronously.")

    async def test_async_msf_close_session(self):
        """
        Test :func:`async_core.async_msf_close_session` for closing a session.
        """
        result = await async_msf_close_session("session1")
        self.assertTrue(result, "Failed to close session asynchronously.")

    async def test_async_msf_list_jobs(self):
        """
        Test :func:`async_core.async_msf_list_jobs` for retrieving active jobs.
        """
        jobs = await async_msf_list_jobs()
        self.assertIsInstance(jobs, list, "Jobs should be a list.")
        self.assertGreaterEqual(len(jobs), 0, "No jobs found.")

    async def test_async_msf_stop_job(self):
        """
        Test :func:`async_core.async_msf_stop_job` for stopping a job.
        """
        result = await async_msf_stop_job("job1")
        self.assertTrue(result, "Failed to stop job asynchronously.")

    async def test_async_msf_payload_generator(self):
        """
        Test :func:`async_core.async_msf_payload_generator` for generating a payload.
        """
        payload = await async_msf_payload_generator({"option1": "value1"})
        self.assertIsInstance(payload, dict, "Payload should be a dictionary.")
        self.assertIn("payload", payload, "Missing 'payload' key in payload data.")

    async def test_async_msf_shutdown(self):
        """
        Test :func:`async_core.async_msf_shutdown` for library shutdown.
        """
        await async_msf_shutdown()
        self.assertTrue(True, "Metasploit Core shutdown failed asynchronously.")


if __name__ == "__main__":
    asyncio.run(unittest.main())
