//! # Assassinate Bridge
//!
//! Rust FFI bridge to Metasploit Framework via Magnus (Ruby embedding).
//!
//! This library provides a native Rust API for interacting with Metasploit Framework
//! by embedding the Ruby VM and bridging to MSF's Ruby API.
//!
//! ## Example (Rust)
//!
//! ```no_run
//! use assassinate_bridge::{Framework, init_metasploit};
//!
//! // Initialize MSF environment
//! init_metasploit("/path/to/metasploit-framework").unwrap();
//!
//! // Create framework instance
//! let framework = Framework::new(None).unwrap();
//!
//! // Get version
//! let version = framework.version().unwrap();
//! println!("MSF Version: {}", version);
//!
//! // List exploits
//! let exploits = framework.list_modules("exploits").unwrap();
//! println!("Found {} exploits", exploits.len());
//! ```
//!
//! ## Note for Python Users
//!
//! Due to Ruby VM threading requirements, this library cannot be used as a Python
//! extension module. Python users should use the IPC-based interface instead, which
//! provides near-FFI performance through high-speed shared memory communication.

pub mod error;
pub mod framework;
pub mod ruby_bridge;

// Re-export main types for Rust users
pub use framework::{
    DataStore, DbManager, Framework, JobManager, Module, PayloadGenerator, Session, SessionManager,
};
pub use ruby_bridge::init_metasploit;
