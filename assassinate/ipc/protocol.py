"""Protocol layer for message serialization.

For now using JSON for simplicity. Can be upgraded to Cap'n Proto later for better performance.
"""

from __future__ import annotations

import json
from typing import Any

from assassinate.ipc.errors import DeserializationError, SerializationError


def serialize_call(call_id: int, method: str, args: list[Any]) -> bytes:
    """Serialize a method call to bytes.

    Args:
        call_id: Unique call identifier
        method: Method name
        args: Method arguments

    Returns:
        Serialized message bytes
    """
    try:
        message = {"call_id": call_id, "request": {"method": method, "args": args}}
        return json.dumps(message).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise SerializationError(f"Failed to serialize call: {e}") from e


def deserialize_response(data: bytes) -> tuple[int, Any | None, dict[str, str] | None]:
    """Deserialize a response message.

    Args:
        data: Serialized message bytes

    Returns:
        Tuple of (call_id, result, error)
        - If successful: (call_id, result, None)
        - If error: (call_id, None, {"code": str, "message": str})
    """
    try:
        message = json.loads(data.decode("utf-8"))
        call_id = message["call_id"]

        if "response" in message:
            return call_id, message["response"].get("result"), None
        elif "error" in message:
            error = message["error"]
            return call_id, None, {"code": error["code"], "message": error["message"]}
        else:
            raise DeserializationError("Unknown message type")

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise DeserializationError(f"Failed to deserialize response: {e}") from e
