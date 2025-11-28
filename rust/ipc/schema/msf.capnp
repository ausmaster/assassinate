@0xb8c3f7e2a1d4e6f9;
# Cap'n Proto schema for Assassinate IPC
# Ultra-low-latency message format for Python <-> Rust/MSF communication

# Value type - represents any JSON-like value
struct Value {
  union {
    null @0 :Void;
    bool @1 :Bool;
    int @2 :Int64;
    float @3 :Float64;
    string @4 :Text;
    bytes @5 :Data;
    list @6 :List(Value);
    map @7 :List(KeyValue);
  }
}

# Key-value pair for map representation
struct KeyValue {
  key @0 :Text;
  value @1 :Value;
}

# MSF method call - request/response envelope
struct MsfCall {
  callId @0 :UInt64;              # Request ID for response matching

  union {
    request @1 :Request;           # This is a request
    response @2 :Response;         # This is a response
    error @3 :Error;               # This is an error
  }
}

# Request message
struct Request {
  method @0 :Text;                 # Method name (e.g., "framework_version")
  args @1 :List(Value);            # Method arguments
}

# Response message
struct Response {
  result @0 :Value;                # Method return value
}

# Error message
struct Error {
  code @0 :Text;                   # Error code (e.g., "ModuleNotFound")
  message @1 :Text;                # Human-readable error message
  details @2 :Value;               # Additional error details (optional)
}

# Ring buffer message envelope
# This is what actually gets written to shared memory
struct Message {
  timestamp @0 :UInt64;            # Nanosecond timestamp for latency tracking
  payload @1 :MsfCall;             # The actual call/response
}

# Control messages for ring buffer management
struct Control {
  union {
    ping @0 :Void;                 # Heartbeat/keep-alive
    shutdown @1 :Void;             # Graceful shutdown signal
    reconnect @2 :Void;            # Request daemon reconnect
  }
}
