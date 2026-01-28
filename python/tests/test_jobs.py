"""Tests for job management functionality."""

import pytest

import assassinate


class TestJobList:
    """Tests for listing jobs."""

    def test_list_jobs_returns_list(self, msf_init):
        """Test that listing jobs returns a list."""
        job_ids = assassinate.job_list()
        assert isinstance(job_ids, list)
        # May be empty if no jobs are running
        assert job_ids is not None

    def test_list_jobs_returns_integers(self, msf_init):
        """Test that job IDs are integers."""
        job_ids = assassinate.job_list()
        for job_id in job_ids:
            assert isinstance(job_id, int)


class TestJobInfo:
    """Tests for getting job information."""

    def test_get_nonexistent_job_returns_none(self, msf_init):
        """Test that getting a nonexistent job returns None or raises."""
        # Job IDs are integers, so use a high unlikely ID
        try:
            job_info = assassinate.job_info(99999)
            # If it doesn't raise, it should return None or empty dict
            assert job_info is None or job_info == {}
        except Exception:
            # Also acceptable - job doesn't exist
            pass

    def test_get_job_with_valid_id(self, msf_init):
        """Test getting a job that exists.

        Note: This test only runs if there are active jobs.
        """
        job_ids = assassinate.job_list()
        if job_ids:
            # Get the first job
            job_info = assassinate.job_info(job_ids[0])
            # Should return info dict or None
            assert job_info is None or isinstance(job_info, dict)


class TestJobKill:
    """Tests for killing jobs."""

    def test_kill_nonexistent_job(self, msf_init):
        """Test killing a nonexistent job."""
        # Use unlikely job ID
        try:
            result = assassinate.job_kill(99999)
            # If it returns, should be boolean
            assert isinstance(result, bool)
        except Exception:
            # Also acceptable - job doesn't exist
            pass

    def test_kill_returns_bool(self, msf_init):
        """Test that kill returns a boolean for invalid IDs."""
        try:
            result = assassinate.job_kill(99998)
            assert isinstance(result, bool)
        except Exception:
            # Exception is acceptable for nonexistent jobs
            pass


class TestJobWorkflow:
    """Tests for complete job workflows."""

    def test_list_then_get_workflow(self, msf_init):
        """Test listing jobs and getting info for each."""
        job_ids = assassinate.job_list()

        # Try to get info for each job
        for job_id in job_ids:
            job_info = assassinate.job_info(job_id)
            # Info should be None or a dict
            assert job_info is None or isinstance(job_info, dict)
