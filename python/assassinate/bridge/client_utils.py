"""Utilities for working with both async and sync clients.

Provides helper functions that can call methods on either MsfClient
or SyncMsfClient transparently.
"""

import inspect
from typing import Any

from assassinate.ipc.protocol import ClientProtocol


async def call_client_method(
    client: ClientProtocol, method_name: str, *args: Any, **kwargs: Any
) -> Any:
    """Call a method on a client, handling both sync and async clients.

    This function automatically detects if the client method returns
    a coroutine (async client) or a direct result (sync client) and
    handles it appropriately.

    Always returns a coroutine that can be awaited, regardless of client type.

    Args:
        client: MsfClient or SyncMsfClient instance
        method_name: Name of the method to call
        *args: Positional arguments to pass
        **kwargs: Keyword arguments to pass

    Returns:
        Result from the method call

    Example:
        >>> # Works with both async and sync clients
        >>> result = await call_client_method(client, "framework_version")
    """
    method = getattr(client, method_name)
    result = method(*args, **kwargs)

    # Check if result is a coroutine (async client)
    if inspect.iscoroutine(result):
        return await result
    else:
        # Sync client - result is already the value
        return result
