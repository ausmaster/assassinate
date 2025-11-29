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

/// Result type alias using AssassinateError
pub type Result<T> = std::result::Result<T, AssassinateError>;
