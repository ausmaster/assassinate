use pyo3::prelude::*;

pub mod error;
pub mod framework;
pub mod ruby_bridge;

use framework::{DataStore, Framework, Module, PayloadGenerator, Session, SessionManager};
use ruby_bridge::init_metasploit;

/// Initialize the Metasploit Framework environment
#[pyfunction]
#[pyo3(signature = (msf_path))]
fn initialize_metasploit(msf_path: String) -> PyResult<()> {
    init_metasploit(&msf_path)?;
    Ok(())
}

/// Get the Metasploit Framework version (convenience function)
#[pyfunction]
fn get_version() -> PyResult<String> {
    let framework = Framework::new(None)?;
    framework.version()
}

/// Python module definition
#[pymodule]
fn assassinate_bridge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add("__doc__", "Rust+Magnus+PyO3 bridge for Python to Metasploit Framework FFI")?;

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

    Ok(())
}
