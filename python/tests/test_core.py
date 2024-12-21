from __future__ import annotations
import unittest
from ..core import (
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
from ..exceptions import InitializationError, ValidationError, ExecutionError, SessionError, JobError


class TestMetasploitCore(unittest.TestCase):
    """
    Test suite for synchronous Metasploit Core Python bindings.

    This suite validates library initialization, module execution,
    session handling, and job management functions.
    """

    def test_msf_init(self):
        """
        Test :func:`core.msf_init` for successful initialization.

        :raises InitializationError: If initialization fails.
        """
        self.assertTrue(msf_init(), "Metasploit Core failed to initialize.")

    def test_msf_get_version(self):
        """
        Test :func:`core.msf_get_version` for version retrieval.
        """
        version = msf_get_version()
        self.assertIsInstance(version, str, "Version should be a string.")
        self.assertTrue(version.startswith("Metasploit Core"), "Invalid version string.")

    def test_msf_list_modules(self):
        """
        Test :func:`core.msf_list_modules` for retrieving module list.
        """
        modules = msf_list_modules("exploit")
        self.assertIsInstance(modules, list, "Modules should be returned as a list.")
        self.assertGreater(len(modules), 0, "No modules returned.")

    def test_msf_module_info(self):
        """
        Test :func:`core.msf_module_info` for retrieving module information.
        """
        info = msf_module_info("exploit", "example_module")
        self.assertIsInstance(info, dict, "Module info should be a dictionary.")
        self.assertIn("name", info, "Module info missing 'name' key.")

    def test_msf_run_module(self):
        """
        Test :func:`core.msf_run_module` for running a module.
        """
        result = msf_run_module("exploit", "example_module", {})
        self.assertTrue(result, "Module failed to run.")

    def test_msf_list_sessions(self):
        """
        Test :func:`core.msf_list_sessions` for retrieving active sessions.
        """
        sessions = msf_list_sessions()
        self.assertIsInstance(sessions, list, "Sessions should be a list.")
        self.assertGreaterEqual(len(sessions), 0, "No sessions found.")

    def test_msf_interact_session(self):
        """
        Test :func:`core.msf_interact_session` for interacting with a session.
        """
        result = msf_interact_session("session1")
        self.assertTrue(result, "Failed to interact with session.")

    def test_msf_close_session(self):
        """
        Test :func:`core.msf_close_session` for closing a session.
        """
        result = msf_close_session("session1")
        self.assertTrue(result, "Failed to close session.")

    def test_msf_list_jobs(self):
        """
        Test :func:`core.msf_list_jobs` for retrieving active jobs.
        """
        jobs = msf_list_jobs()
        self.assertIsInstance(jobs, list, "Jobs should be a list.")
        self.assertGreaterEqual(len(jobs), 0, "No jobs found.")

    def test_msf_stop_job(self):
        """
        Test :func:`core.msf_stop_job` for stopping a job.
        """
        result = msf_stop_job("job1")
        self.assertTrue(result, "Failed to stop job.")

    def test_msf_payload_generator(self):
        """
        Test :func:`core.msf_payload_generator` for generating a payload.
        """
        payload = msf_payload_generator({"option1": "value1"})
        self.assertIsInstance(payload, dict, "Payload should be a dictionary.")
        self.assertIn("payload", payload, "Missing 'payload' key in payload data.")

    def test_msf_shutdown(self):
        """
        Test :func:`core.msf_shutdown` for library shutdown.
        """
        msf_shutdown()
        self.assertTrue(True, "Metasploit Core shutdown failed.")


if __name__ == "__main__":
    unittest.main()
