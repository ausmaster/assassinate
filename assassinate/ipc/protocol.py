"""Protocol definitions for client interfaces.

Defines the common interface that both async and sync clients implement.
Also provides message serialization functions.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import msgpack

from assassinate.ipc.errors import DeserializationError, SerializationError


@runtime_checkable
class ClientProtocol(Protocol):
    """Protocol that both MsfClient and SyncMsfClient implement.

    This allows bridge classes to accept either client type and work
    transparently with both sync and async code.
    """

    # Framework methods
    def framework_version(self) -> Any: ...
    def list_modules(self, module_type: str) -> Any: ...
    def search(self, query: str) -> Any: ...
    def threads(self) -> Any: ...

    # Module methods
    def create_module(self, module_path: str) -> Any: ...
    def module_info(self, module_id: str) -> Any: ...
    def module_set_option(
        self, module_id: str, key: str, value: str
    ) -> Any: ...
    def module_get_option(self, module_id: str, key: str) -> Any: ...
    def module_options(self, module_id: str) -> Any: ...
    def module_validate(self, module_id: str) -> Any: ...
    def module_compatible_payloads(self, module_id: str) -> Any: ...
    def module_check(self, module_id: str) -> Any: ...
    def module_has_check(self, module_id: str) -> Any: ...
    def module_targets(self, module_id: str) -> Any: ...
    def module_aliases(self, module_id: str) -> Any: ...
    def module_notes(self, module_id: str) -> Any: ...
    def module_exploit(
        self,
        module_id: str,
        payload: str,
        options: dict[str, str] | None = None,
    ) -> Any: ...
    def module_run(
        self, module_id: str, options: dict[str, str] | None = None
    ) -> Any: ...
    def delete_module(self, module_id: str) -> Any: ...

    # Session methods
    def list_sessions(self) -> Any: ...
    def session_get(self, session_id: int) -> Any: ...
    def session_kill(self, session_id: int) -> Any: ...
    def session_info(self, session_id: int) -> Any: ...
    def session_type(self, session_id: int) -> Any: ...
    def session_alive(self, session_id: int) -> Any: ...
    def session_read(
        self, session_id: int, length: int | None = None
    ) -> Any: ...
    def session_write(self, session_id: int, data: str) -> Any: ...
    def session_execute(self, session_id: int, command: str) -> Any: ...
    def session_run_cmd(self, session_id: int, command: str) -> Any: ...

    # DataStore methods
    def framework_get_option(self, key: str) -> Any: ...
    def framework_set_option(self, key: str, value: str) -> Any: ...
    def framework_datastore_to_dict(self) -> Any: ...
    def framework_delete_option(self, key: str) -> Any: ...
    def framework_clear_datastore(self) -> Any: ...
    def module_datastore_to_dict(self, module_id: str) -> Any: ...
    def module_delete_option(self, module_id: str, key: str) -> Any: ...
    def module_clear_datastore(self, module_id: str) -> Any: ...


def is_async_client(client: ClientProtocol) -> bool:
    """Check if a client is async (MsfClient) or sync (SyncMsfClient).

    Args:
        client: Client instance

    Returns:
        True if client is async (MsfClient), False if sync (SyncMsfClient)
    """
    # Import here to avoid circular dependency
    from assassinate.ipc.client import MsfClient

    return isinstance(client, MsfClient)


def serialize_call(call_id: int, method: str, args: list[Any]) -> bytes:
    """Serialize a method call to bytes using MessagePack.

    Args:
        call_id: Unique call identifier
        method: Method name
        args: Method arguments

    Returns:
        Serialized message bytes
    """
    try:
        message = {
            "call_id": call_id,
            "request": {"method": method, "args": args},
        }
        return msgpack.packb(message, use_bin_type=True)
    except (TypeError, ValueError) as e:
        raise SerializationError(f"Failed to serialize call: {e}") from e


def deserialize_response(
    data: bytes,
) -> tuple[int, Any | None, dict[str, str] | None]:
    """Deserialize a response message using MessagePack.

    Args:
        data: Serialized message bytes

    Returns:
        Tuple of (call_id, result, error)
        - If successful: (call_id, result, None)
        - If error: (call_id, None, {"code": str, "message": str})
    """
    try:
        message = msgpack.unpackb(data, raw=False)
        call_id = message["call_id"]

        if "response" in message and message["response"] is not None:
            response_data = message["response"]
            # Response contains {"result": ...}
            if isinstance(response_data, dict) and "result" in response_data:
                return call_id, response_data["result"], None
            # Fallback for backward compatibility
            return call_id, response_data, None
        elif "error" in message and message["error"] is not None:
            error = message["error"]
            return (
                call_id,
                None,
                {"code": error["code"], "message": error["message"]},
            )
        else:
            raise DeserializationError("Unknown message type")

    except (
        msgpack.exceptions.UnpackException,
        KeyError,
        ValueError,
        TypeError,
    ) as e:
        raise DeserializationError(
            f"Failed to deserialize response: {e}"
        ) from e
