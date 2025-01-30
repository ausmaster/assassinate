use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use crate::ruby_bridge::*;

/// Python wrapper for `init_ruby`
#[pyfunction]
fn py_init_ruby() {
    unsafe { init_ruby() };
}

/// Python wrapper for `get_metasploit_version`
#[pyfunction]
fn py_get_metasploit_version() -> PyResult<String> {
    get_metasploit_version().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Python wrapper for `list_metasploit_modules`
#[pyfunction]
fn py_list_metasploit_modules() -> PyResult<String> {
    list_metasploit_modules().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Python wrapper for `run_metasploit_module`
#[pyfunction]
fn py_run_metasploit_module(module: String, options: String) -> PyResult<String> {
    run_metasploit_module(&module, &options)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Define Python module
#[pymodule]
fn metasploit_python_bridge(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_init_ruby, m)?)?;
    m.add_function(wrap_pyfunction!(py_get_metasploit_version, m)?)?;
    m.add_function(wrap_pyfunction!(py_list_metasploit_modules, m)?)?;
    m.add_function(wrap_pyfunction!(py_run_metasploit_module, m)?)?;
    Ok(())
}
