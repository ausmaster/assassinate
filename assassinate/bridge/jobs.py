"""MSF Job management.

Provides access to background jobs for running modules asynchronously.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from assassinate.bridge.client_utils import call_client_method

if TYPE_CHECKING:
    from assassinate.ipc.protocol import ClientProtocol


class JobManager:
    """Job manager for MSF.

    Manages background jobs for running modules asynchronously.

    Now uses IPC for all operations.
    """

    _client: ClientProtocol

    def __init__(self, client: ClientProtocol) -> None:
        """Initialize JobManager instance.

        Args:
            client: IPC client (MsfClient or SyncMsfClient) to use.

        Example:
            >>> from assassinate.ipc import MsfClient
            >>> client = MsfClient()
            >>> await client.connect()
            >>> jm = JobManager(client)
        """
        self._client = client

    async def list(self) -> list[str]:
        """List all active job IDs.

        Returns:
            List of job IDs.

        Example:
            >>> jm = JobManager(client)
            >>> job_ids = await jm.list()
            >>> print(f"Active jobs: {len(job_ids)}")
        """
        result = await call_client_method(self._client, "job_list")
        return list(result)

    async def get(self, job_id: str) -> str | None:
        """Get job information by ID.

        Args:
            job_id: Job ID to retrieve.

        Returns:
            Job information string or None if not found.

        Example:
            >>> jm = JobManager(client)
            >>> job = await jm.get("0")
            >>> if job:
            ...     print(job)
        """
        result = await call_client_method(self._client, "job_get", job_id)
        return str(result) if result is not None else None

    async def kill(self, job_id: str) -> bool:
        """Kill a job by ID.

        Args:
            job_id: Job ID to terminate.

        Returns:
            True if job was killed, False if not found.

        Example:
            >>> jm = JobManager(client)
            >>> if await jm.kill("0"):
            ...     print("Job killed")
        """
        result = await call_client_method(self._client, "job_kill", job_id)
        return bool(result)

    def __repr__(self) -> str:
        """Return string representation of JobManager.

        Returns:
            String representation.
        """
        # Don't call async methods in __repr__ - return static string
        return "<JobManager>"
