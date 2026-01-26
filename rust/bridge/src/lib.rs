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
//! use msf::{Framework, init_metasploit};
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
//! ## Python Bindings
//!
//! When compiled with the `pyo3` feature, this library provides the `msf` Python module:
//!
//! ```python
//! from msf import init_msf, create_module
//!
//! init_msf("/path/to/metasploit-framework")
//! module = create_module("exploit/linux/samba/is_known_pipename")
//! module.options.RHOSTS = "192.168.1.100"  # Attribute-style access
//! session = module.exploit("cmd/unix/interact")
//! ```
//!
//! ## Logging
//!
//! This crate uses the `log` crate for logging. When compiled with the `pyo3` feature,
//! logs are automatically bridged to Python's `logging` module via `pyo3-log`.
//!
//! - Rust logs with `target: "msf::module"` appear as Python logger `msf.module`
//! - Log levels: TRACE→DEBUG, DEBUG→DEBUG, INFO→INFO, WARN→WARNING, ERROR→ERROR
//!
//! Configure logging from Python:
//! ```python
//! import logging
//! logging.basicConfig(level=logging.DEBUG)
//! ```

// Re-export log macros for use throughout the crate
pub use log::{debug, error, info, trace, warn};

pub mod error;
pub mod framework;
pub mod gvl;
pub mod ruby_bridge;
pub mod ruby_bootstrap;

// Re-export main types for Rust users
pub use framework::{
    DataStore, DbManager, Framework, JobManager, Module, PayloadGenerator, PluginManager, Session,
    SessionManager,
};
pub use ruby_bootstrap::{ensure_ruby, init_ruby, require_all};
pub use ruby_bridge::{init_metasploit, Options, RubyVal};

// =============================================================================
// Python Bindings (pyo3 feature)
// =============================================================================

/// Python module providing MSF bindings when the `pyo3` feature is enabled.
///
/// The module is named `assassinate_pyo3` and provides:
/// - `PySession` - Session wrapper with 70+ methods
/// - `ExploitModule` - Module wrapper with metadata, options, and execution
/// - Module-level functions for framework operations
///
/// ## Usage from Python
///
/// ```python
/// from msf import init_msf, create_module
///
/// init_msf("/path/to/metasploit-framework")
/// module = create_module("exploit/linux/samba/is_known_pipename")
/// module.options.RHOSTS = "192.168.1.100"  # Attribute-style access
/// session = module.exploit("cmd/unix/interact")
/// if session:
///     print(session.run_cmd("whoami"))
/// ```
#[cfg(feature = "pyo3")]
pub mod pyo3;

// Re-export the pymodule initializer for maturin
#[cfg(feature = "pyo3")]
pub use pyo3::msf;
