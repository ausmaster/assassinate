//! Error types for the Assassinate bridge

use thiserror::Error;

// Only import PyO3 types when python-bindings feature is enabled
#[cfg(feature = "python-bindings")]
use pyo3::exceptions::PyRuntimeError;
#[cfg(feature = "python-bindings")]
use pyo3::PyErr;

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

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<magnus::Error> for AssassinateError {
    fn from(err: magnus::Error) -> Self {
        AssassinateError::RubyError(err.to_string())
    }
}

// Only implement PyErr conversion when python-bindings feature is enabled
#[cfg(feature = "python-bindings")]
impl From<AssassinateError> for PyErr {
    fn from(err: AssassinateError) -> PyErr {
        PyRuntimeError::new_err(err.to_string())
    }
}

/// Result type alias using AssassinateError
///
/// This type automatically converts to PyResult when used in Python bindings
pub type Result<T> = std::result::Result<T, AssassinateError>;
