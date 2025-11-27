//! # Assassinate Bridge
//!
//! Rust FFI bridge to Metasploit Framework via Magnus (Ruby embedding).
//!
//! This library provides a native Rust API for interacting with Metasploit Framework
//! by embedding the Ruby VM and bridging to MSF's Ruby API.
//!
//! ## Features
//!
//! - `python-bindings` (default): Enable Python bindings via PyO3
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

#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;

pub mod error;
pub mod framework;
pub mod ruby_bridge;

// Re-export main types for Rust users
pub use framework::{
    DataStore, DbManager, Framework, JobManager, Module, PayloadGenerator, Session, SessionManager,
};
pub use ruby_bridge::init_metasploit;

// Python bindings (only compiled when python-bindings feature is enabled)
#[cfg(feature = "python-bindings")]
mod python_bindings {
    use super::*;

    /// Initialize the Metasploit Framework environment
    #[pyfunction]
    #[pyo3(signature = (msf_path))]
    fn initialize_metasploit(msf_path: String) -> PyResult<()> {
        super::init_metasploit(&msf_path)?;
        Ok(())
    }

    /// Get the Metasploit Framework version (convenience function)
    #[pyfunction]
    fn get_version() -> PyResult<String> {
        let framework = Framework::new(None)?;
        Ok(framework.version()?)
    }

    /// Python module definition
    #[pymodule]
    fn assassinate_bridge(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", "0.1.0")?;
        m.add(
            "__doc__",
            "Rust FFI bridge to Metasploit Framework (Magnus → Ruby) with Python bindings (PyO3)",
        )?;

        // Add functions
        m.add_function(wrap_pyfunction!(initialize_metasploit, m)?)?;
        m.add_function(wrap_pyfunction!(get_version, m)?)?;

        // Add classes
        m.add_class::<Framework>()?;
        m.add_class::<Module>()?;
        m.add_class::<DataStore>()?;
        m.add_class::<SessionManager>()?;
        m.add_class::<Session>()?;
        m.add_class::<PayloadGenerator>()?;
        m.add_class::<DbManager>()?;
        m.add_class::<JobManager>()?;

        Ok(())
    }
}
