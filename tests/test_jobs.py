"""Tests for JobManager functionality."""

import pytest


@pytest.mark.integration
class TestJobList:
    """Tests for listing jobs."""

    async def test_list_jobs_returns_list(self, client):
        """Test that listing jobs returns a list."""
        job_ids = await client.job_list()
        assert isinstance(job_ids, list)
        # May be empty if no jobs are running
        assert job_ids is not None

    async def test_list_jobs_returns_strings(self, client):
        """Test that job IDs are strings."""
        job_ids = await client.job_list()
        for job_id in job_ids:
            assert isinstance(job_id, str)


@pytest.mark.integration
class TestJobGet:
    """Tests for getting job information."""

    async def test_get_nonexistent_job_returns_none(self, client):
        """Test that getting a nonexistent job returns None."""
        job_info = await client.job_get("nonexistent_job_id_12345")
        assert job_info is None

    async def test_get_job_with_valid_id(self, client):
        """Test getting a job that exists.

        Note: This test only runs if there are active jobs.
        """
        job_ids = await client.job_list()
        if job_ids:
            # Get the first job
            job_info = await client.job_get(job_ids[0])
            # Should return either None or a string
            assert job_info is None or isinstance(job_info, str)


@pytest.mark.integration
class TestJobKill:
    """Tests for killing jobs."""

    async def test_kill_nonexistent_job(self, client):
        """Test killing a nonexistent job.

        MSF returns false when killing nonexistent jobs.
        """
        result = await client.job_kill("nonexistent_job_id_12345")
        assert isinstance(result, bool)
        # Usually returns False for nonexistent jobs
        assert result is False

    async def test_kill_returns_bool(self, client):
        """Test that kill always returns a boolean."""
        result = await client.job_kill("test_id")
        assert isinstance(result, bool)


@pytest.mark.integration
class TestJobWorkflow:
    """Tests for complete job workflows."""

    async def test_list_then_get_workflow(self, client):
        """Test listing jobs and getting info for each."""
        job_ids = await client.job_list()

        # Try to get info for each job
        for job_id in job_ids:
            job_info = await client.job_get(job_id)
            # Info should be None or a string
            assert job_info is None or isinstance(job_info, str)

    async def test_job_operations_dont_crash(self, client):
        """Test that job operations don't crash with empty/invalid inputs."""
        # These should not raise exceptions
        await client.job_list()
        await client.job_get("")
        await client.job_get("invalid")

        # Kill operations should return False for invalid IDs
        result = await client.job_kill("")
        assert isinstance(result, bool)

        result = await client.job_kill("invalid_id")
        assert isinstance(result, bool)
