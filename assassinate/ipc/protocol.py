"""Protocol layer for message serialization.

Using MessagePack for high-performance binary serialization
(~5-10x faster than JSON).
"""

from __future__ import annotations

from typing import Any

import msgpack

from assassinate.ipc.errors import DeserializationError, SerializationError


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
