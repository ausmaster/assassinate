//! Pyo3 wrapper macros for reducing boilerplate
//!
//! ## Why Macros?
//!
//! Pyo3's `#[pymethods]` proc macro rejects declarative macros inside impl blocks.
//! The workaround is to generate SEPARATE `#[pymethods] impl` blocks for each method.
//! This requires the `multiple-pymethods` feature (uses `inventory` crate).
//!
//! ## Error Handling
//!
//! All macros use `?` operator which works because we implement
//! `From<AssassinateError> for PyErr` in `error.rs`.

/// Generate a simple wrapper method that returns a primitive type
///
/// # Examples
///
/// ```ignore
/// // No arguments
/// pyo3_wrap!(PySession, session, session_type() -> String);
///
/// // One argument
/// pyo3_wrap!(PySession, session, fs_chdir(path: &str) -> ());
///
/// // Two arguments
/// pyo3_wrap!(PySession, session, fs_mv(old: &str, new: &str) -> ());
/// ```
#[macro_export]
macro_rules! pyo3_wrap {
    // No arguments
    ($class:ty, $inner:ident, $method:ident() -> $ret:ty) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self) -> pyo3::PyResult<$ret> {
                Ok(self.$inner.$method()?)
            }
        }
    };
    // One argument
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty) -> $ret:ty) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1) -> pyo3::PyResult<$ret> {
                Ok(self.$inner.$method($arg1)?)
            }
        }
    };
    // Two arguments
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty, $arg2:ident : $ty2:ty) -> $ret:ty) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1, $arg2: $ty2) -> pyo3::PyResult<$ret> {
                Ok(self.$inner.$method($arg1, $arg2)?)
            }
        }
    };
    // Three arguments
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty, $arg2:ident : $ty2:ty, $arg3:ident : $ty3:ty) -> $ret:ty) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1, $arg2: $ty2, $arg3: $ty3) -> pyo3::PyResult<$ret> {
                Ok(self.$inner.$method($arg1, $arg2, $arg3)?)
            }
        }
    };
}

/// Generate a wrapper method that returns `serde_json::Value` as a Python object
///
/// # Examples
///
/// ```ignore
/// pyo3_wrap_json!(PySession, session, fs_stat(path: &str));
/// pyo3_wrap_json!(PySession, session, sys_sysinfo());
/// ```
#[macro_export]
macro_rules! pyo3_wrap_json {
    // No arguments
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
                let value = self.$inner.$method()?;
                $crate::pyo3::conversions::json_to_py(py, &value)
            }
        }
    };
    // One argument
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty)) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, py: pyo3::Python<'_>, $arg1: $ty1) -> pyo3::PyResult<pyo3::PyObject> {
                let value = self.$inner.$method($arg1)?;
                $crate::pyo3::conversions::json_to_py(py, &value)
            }
        }
    };
}

/// Generate a wrapper method that returns `Vec<serde_json::Value>` as a Python list
///
/// # Examples
///
/// ```ignore
/// pyo3_wrap_json_vec!(PySession, session, process_list());
/// pyo3_wrap_json_vec!(PySession, session, net_get_interfaces());
/// ```
#[macro_export]
macro_rules! pyo3_wrap_json_vec {
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
                let values = self.$inner.$method()?;
                $crate::pyo3::conversions::json_vec_to_py(py, values)
            }
        }
    };
}

/// Generate a wrapper method that returns `HashMap<String, String>` as a Python dict
///
/// # Examples
///
/// ```ignore
/// pyo3_wrap_hashmap!(ExploitModule, module, notes());
/// ```
#[macro_export]
macro_rules! pyo3_wrap_hashmap {
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pyo3::pymethods]
        impl $class {
            fn $method(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
                let map = self.$inner.$method()?;
                $crate::pyo3::conversions::hashmap_to_py(py, map)
            }
        }
    };
}

// Re-export macros at module level
pub use pyo3_wrap;
pub use pyo3_wrap_hashmap;
pub use pyo3_wrap_json;
pub use pyo3_wrap_json_vec;
