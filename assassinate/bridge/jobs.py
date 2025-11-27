"""MSF Job management.

Provides access to background jobs for running modules asynchronously.
"""

from __future__ import annotations

from typing import Any


class JobManager:
    """Job manager for MSF.

    Manages background jobs for running modules asynchronously.
    """

    _instance: Any  # The underlying PyO3 JobManager instance

    def __init__(self, instance: Any) -> None:
        """Initialize JobManager wrapper.

        Args:
            instance: PyO3 JobManager instance.

        Note:
            This is called internally via Framework.jobs().
        """
        self._instance = instance

    def list(self) -> list[str]:
        """List all active job IDs.

        Returns:
            List of job IDs.

        Example:
            >>> jm = fw.jobs()
            >>> job_ids = jm.list()
            >>> print(f"Active jobs: {len(job_ids)}")
        """
        return list(self._instance.list())

    def get(self, job_id: str) -> str | None:
        """Get job information by ID.

        Args:
            job_id: Job ID to retrieve.

        Returns:
            Job information string or None if not found.

        Example:
            >>> jm = fw.jobs()
            >>> job = jm.get("0")
            >>> if job:
            ...     print(job)
        """
        result = self._instance.get(job_id)
        return str(result) if result is not None else None

    def kill(self, job_id: str) -> bool:
        """Kill a job by ID.

        Args:
            job_id: Job ID to terminate.

        Returns:
            True if job was killed, False if not found.

        Example:
            >>> jm = fw.jobs()
            >>> if jm.kill("0"):
            ...     print("Job killed")
        """
        return bool(self._instance.kill(job_id))

    def __repr__(self) -> str:
        """Return string representation of JobManager.

        Returns:
            String representation.
        """
        job_count = len(self.list())
        return f"<JobManager jobs={job_count}>"
