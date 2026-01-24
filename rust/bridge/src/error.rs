//! Error types for the Assassinate bridge

use thiserror::Error;

/// Core error type for the Assassinate bridge
#[derive(Error, Debug)]
pub enum AssassinateError {
    #[error("Ruby initialization failed: {0}")]
    RubyInitError(String),

    #[error("Ruby execution error: {0}")]
    RubyError(String),

    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error("Invalid module type: {0}")]
    InvalidModuleType(String),

    #[error("Module validation failed: {0}")]
    ModuleValidationError(String),

    #[error("Module execution failed: {0}")]
    ModuleExecutionError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Session not found: {0}")]
    SessionNotFound(i64),

    #[error("DataStore error: {0}")]
    DataStoreError(String),

    #[error("Payload generation error: {0}")]
    PayloadError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Type conversion error: {0}")]
    ConversionError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<magnus::Error> for AssassinateError {
    fn from(err: magnus::Error) -> Self {
        AssassinateError::RubyError(err.to_string())
    }
}

/// Result type alias using AssassinateError
pub type Result<T> = std::result::Result<T, AssassinateError>;

// =============================================================================
// Pyo3 Error Conversion
// =============================================================================

/// Convert AssassinateError to PyErr when the pyo3 feature is enabled
///
/// This implementation allows using the `?` operator directly in #[pyfunction]
/// and #[pymethods] without calling `to_py_result()` manually.
///
/// # Example
///
/// ```ignore
/// #[pyfunction]
/// fn framework_version() -> PyResult<String> {
///     // The ? operator automatically converts AssassinateError -> PyErr
///     Ok(with_framework(|fw| fw.version())?)
/// }
/// ```
#[cfg(feature = "pyo3")]
impl From<AssassinateError> for pyo3::PyErr {
    fn from(err: AssassinateError) -> Self {
        // Use the custom AssassinateError exception from the pymodule
        crate::pyo3::AssassinateError::new_err(err.to_string())
    }
}
