//! Thread-local Framework singleton
//!
//! This module provides a thread-local Framework instance that module-level
//! Python functions can use. This is necessary because:
//!
//! 1. Python doesn't have a natural way to pass the Framework to every function
//! 2. MSF's embedded Ruby VM is not thread-safe
//! 3. The `unsendable` pyclass attribute ensures we stay on the main thread
//!
//! ## Usage Pattern
//!
//! ```ignore
//! // Initialize once at module load
//! init_msf("/path/to/msf")?;
//!
//! // All subsequent calls use the singleton
//! let version = framework_version()?;
//! let modules = list_modules("exploit")?;
//! ```

use std::cell::RefCell;

use crate::error::AssassinateError;
use crate::Framework;

thread_local! {
    /// Thread-local storage for the Framework singleton
    ///
    /// Uses `RefCell` for interior mutability since we need to set it once
    /// during `init_msf()` and then only read it afterwards.
    pub(crate) static FRAMEWORK: RefCell<Option<Framework>> = const { RefCell::new(None) };
}

/// Execute a function with the Framework singleton
///
/// Returns an error if `init_msf()` hasn't been called yet.
///
/// # Example
///
/// ```ignore
/// fn framework_version() -> PyResult<String> {
///     with_framework(|fw| Ok(fw.version()?))
/// }
/// ```
pub fn with_framework<F, R>(f: F) -> Result<R, AssassinateError>
where
    F: FnOnce(&Framework) -> Result<R, AssassinateError>,
{
    FRAMEWORK.with(|cell| {
        let guard = cell.borrow();
        match guard.as_ref() {
            Some(framework) => f(framework),
            None => Err(AssassinateError::RubyInitError(
                "Framework not initialized. Call init_msf() first.".to_string(),
            )),
        }
    })
}

/// Set the Framework singleton
///
/// Called by `init_msf()` after successful initialization.
/// Only sets the framework if it hasn't been set already.
pub fn set_framework(framework: Framework) {
    FRAMEWORK.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            *guard = Some(framework);
        }
    });
}

/// Check if the Framework has been initialized
pub fn is_initialized() -> bool {
    FRAMEWORK.with(|cell| cell.borrow().is_some())
}
