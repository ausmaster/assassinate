/// Protocol layer for MessagePack message handling
///
/// Using MessagePack for high-performance binary serialization.
/// ~5-10x faster than JSON with smaller message sizes.

use crate::error::{IpcError, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Request {
    method: String,
    args: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    result: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
struct Error {
    code: String,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    call_id: u64,
    request: Option<Request>,
    response: Option<Response>,
    error: Option<Error>,
}

/// Serialize an MSF call to bytes using MessagePack
pub fn serialize_call(
    call_id: u64,
    method: &str,
    args: Vec<serde_json::Value>,
) -> Result<Vec<u8>> {
    let message = Message {
        call_id,
        request: Some(Request {
            method: method.to_string(),
            args,
        }),
        response: None,
        error: None,
    };

    rmp_serde::to_vec_named(&message).map_err(|e| IpcError::Serialization(e.to_string()))
}

/// Deserialize an MSF call from bytes
pub fn deserialize_call(data: &[u8]) -> Result<(u64, String, Vec<serde_json::Value>)> {
    let message: Message =
        rmp_serde::from_slice(data).map_err(|e| IpcError::Deserialization(e.to_string()))?;

    if let Some(request) = message.request {
        Ok((message.call_id, request.method, request.args))
    } else {
        Err(IpcError::Deserialization(
            "Expected request message".to_string(),
        ))
    }
}

/// Serialize a response
pub fn serialize_response(call_id: u64, result: serde_json::Value) -> Result<Vec<u8>> {
    let message = Message {
        call_id,
        request: None,
        response: Some(Response { result }),
        error: None,
    };

    rmp_serde::to_vec_named(&message).map_err(|e| IpcError::Serialization(e.to_string()))
}

/// Serialize an error
pub fn serialize_error(call_id: u64, code: &str, message: &str) -> Result<Vec<u8>> {
    let msg = Message {
        call_id,
        request: None,
        response: None,
        error: Some(Error {
            code: code.to_string(),
            message: message.to_string(),
        }),
    };

    rmp_serde::to_vec(&msg).map_err(|e| IpcError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_call() {
        let call_id = 42;
        let method = "framework_version";
        let args = vec![];

        let bytes = serialize_call(call_id, method, args.clone()).unwrap();
        let (parsed_id, parsed_method, parsed_args) = deserialize_call(&bytes).unwrap();

        assert_eq!(parsed_id, call_id);
        assert_eq!(parsed_method, method);
        assert_eq!(parsed_args, args);
    }
}
