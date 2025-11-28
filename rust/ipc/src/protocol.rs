/// Protocol layer for JSON message handling
///
/// Using JSON for simplicity and Python compatibility.
/// Can be upgraded to Cap'n Proto later for better performance.

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
#[serde(untagged)]
enum MessageType {
    Request { request: Request },
    Response { response: Response },
    Error { error: Error },
}

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    call_id: u64,
    #[serde(flatten)]
    msg_type: MessageType,
}

/// Serialize an MSF call to bytes using JSON
pub fn serialize_call(
    call_id: u64,
    method: &str,
    args: Vec<serde_json::Value>,
) -> Result<Vec<u8>> {
    let message = Message {
        call_id,
        msg_type: MessageType::Request {
            request: Request {
                method: method.to_string(),
                args,
            },
        },
    };

    serde_json::to_vec(&message).map_err(|e| IpcError::Serialization(e.to_string()))
}

/// Deserialize an MSF call from bytes
pub fn deserialize_call(data: &[u8]) -> Result<(u64, String, Vec<serde_json::Value>)> {
    let message: Message =
        serde_json::from_slice(data).map_err(|e| IpcError::Deserialization(e.to_string()))?;

    match message.msg_type {
        MessageType::Request { request } => Ok((message.call_id, request.method, request.args)),
        _ => Err(IpcError::Deserialization(
            "Expected request message".to_string(),
        )),
    }
}

/// Serialize a response
pub fn serialize_response(call_id: u64, result: serde_json::Value) -> Result<Vec<u8>> {
    let message = Message {
        call_id,
        msg_type: MessageType::Response {
            response: Response { result },
        },
    };

    serde_json::to_vec(&message).map_err(|e| IpcError::Serialization(e.to_string()))
}

/// Serialize an error
pub fn serialize_error(call_id: u64, code: &str, message: &str) -> Result<Vec<u8>> {
    let msg = Message {
        call_id,
        msg_type: MessageType::Error {
            error: Error {
                code: code.to_string(),
                message: message.to_string(),
            },
        },
    };

    serde_json::to_vec(&msg).map_err(|e| IpcError::Serialization(e.to_string()))
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
