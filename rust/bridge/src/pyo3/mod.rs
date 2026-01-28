//! Pyo3 Python bindings for the Assassinate bridge
//!
//! This module provides Python bindings when the `pyo3` feature is enabled.
//! It exposes the same functionality as the Rust API but with Python-friendly types.
//!
//! ## Module Structure
//!
//! - `conversions` - Type conversion utilities (JSON/HashMap to Python)
//! - `macros` - Declarative macros for reducing boilerplate
//! - `singleton` - Thread-local Framework singleton for module-level functions
//! - `pymodule` - The actual Python module definition with classes and functions

pub mod conversions;
#[macro_use]
pub mod macros;
pub mod pymodule;
pub mod singleton;

// Re-export the Python module initializer
pub use pymodule::_rust;

// Re-export the custom exception for use in other modules
pub use pymodule::AssassinateError;
