/// Protocol layer for Cap'n Proto message handling

use crate::error::{IpcError, Result};
use crate::msf_capnp;
use capnp::message::{Builder, ReaderOptions};
use capnp::serialize;

/// Serialize an MSF call to bytes using Cap'n Proto
pub fn serialize_call(
    call_id: u64,
    method: &str,
    args: Vec<serde_json::Value>,
) -> Result<Vec<u8>> {
    let mut message = Builder::new_default();
    let mut call = message.init_root::<msf_capnp::msf_call::Builder>();

    call.set_call_id(call_id);

    // Build request
    let mut request = call.init_request();
    request.set_method(method);

    // TODO: Convert args to Cap'n Proto Value list
    // For now, just create empty list
    let _args_list = request.init_args(args.len() as u32);

    // Serialize to bytes
    let mut buf = Vec::new();
    serialize::write_message(&mut buf, &message)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    Ok(buf)
}

/// Deserialize an MSF call from bytes
pub fn deserialize_call(data: &[u8]) -> Result<(u64, String, Vec<serde_json::Value>)> {
    let reader_options = ReaderOptions::default();
    let message = serialize::read_message(data, reader_options)
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    let call = message
        .get_root::<msf_capnp::msf_call::Reader>()
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    let call_id = call.get_call_id();

    match call.which() {
        Ok(msf_capnp::msf_call::Which::Request(request)) => {
            let request = request.map_err(|e| IpcError::Deserialization(e.to_string()))?;
            let method = request
                .get_method()
                .map_err(|e| IpcError::Deserialization(e.to_string()))?
                .to_string()
                .map_err(|e| IpcError::Deserialization(e.to_string()))?;

            // TODO: Convert Cap'n Proto args to serde_json::Value
            let args = Vec::new();

            Ok((call_id, method, args))
        }
        Ok(msf_capnp::msf_call::Which::Response(_)) => {
            Err(IpcError::Deserialization("Expected request, got response".to_string()))
        }
        Ok(msf_capnp::msf_call::Which::Error(_)) => {
            Err(IpcError::Deserialization("Expected request, got error".to_string()))
        }
        Err(e) => Err(IpcError::Deserialization(format!("Unknown message type: {:?}", e))),
    }
}

/// Serialize a response
pub fn serialize_response(call_id: u64, result: serde_json::Value) -> Result<Vec<u8>> {
    let mut message = Builder::new_default();
    let mut call = message.init_root::<msf_capnp::msf_call::Builder>();

    call.set_call_id(call_id);

    // Build response
    let _response = call.init_response();
    // TODO: Convert result to Cap'n Proto Value

    // Serialize to bytes
    let mut buf = Vec::new();
    serialize::write_message(&mut buf, &message)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    Ok(buf)
}

/// Serialize an error
pub fn serialize_error(call_id: u64, code: &str, message: &str) -> Result<Vec<u8>> {
    let mut msg = Builder::new_default();
    let mut call = msg.init_root::<msf_capnp::msf_call::Builder>();

    call.set_call_id(call_id);

    // Build error
    let mut error = call.init_error();
    error.set_code(code);
    error.set_message(message);

    // Serialize to bytes
    let mut buf = Vec::new();
    serialize::write_message(&mut buf, &msg)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    Ok(buf)
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
