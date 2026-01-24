//! Pyo3 wrapper macros for reducing boilerplate
//!
//! ## Solution: `multiple-pymethods` Feature
//!
//! Pyo3's `#[pymethods]` proc macro rejects declarative macros inside impl blocks.
//! The workaround is to:
//! 1. Enable the `multiple-pymethods` feature (uses `inventory` crate)
//! 2. Generate SEPARATE `#[pymethods] impl` blocks for each method
//! 3. The macro expands before the proc macro runs, so it only sees valid Rust
//!
//! This approach is officially supported and tested by Pyo3.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use bridge::error::AssassinateError as BridgeError;

/// Convert a bridge Result to a PyResult
pub fn to_py_result<T>(res: Result<T, BridgeError>) -> PyResult<T> {
    res.map_err(|e| crate::AssassinateError::new_err(e.to_string()))
}

/// Convert serde_json::Value to PyObject
pub fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    use pyo3::ToPyObject;
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.to_object(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.to_object(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.to_object(py))
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(s) => Ok(s.to_object(py)),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into())
        }
    }
}

/// Convert Vec<serde_json::Value> to PyObject (list)
pub fn json_vec_to_py(py: Python<'_>, values: Vec<serde_json::Value>) -> PyResult<PyObject> {
    let list = PyList::empty_bound(py);
    for value in values {
        list.append(json_to_py(py, &value)?)?;
    }
    Ok(list.into())
}

/// Convert HashMap<String, String> to PyObject (dict)
pub fn hashmap_to_py(py: Python<'_>, map: std::collections::HashMap<String, String>) -> PyResult<PyObject> {
    let dict = PyDict::new_bound(py);
    for (k, v) in map {
        dict.set_item(k, v)?;
    }
    Ok(dict.into())
}

/// Generate a simple wrapper method (returns primitive type)
macro_rules! pyo3_wrap {
    ($class:ty, $inner:ident, $method:ident() -> $ret:ty) => {
        #[pymethods]
        impl $class {
            fn $method(&self) -> PyResult<$ret> {
                $crate::macros::to_py_result(self.$inner.$method())
            }
        }
    };
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty) -> $ret:ty) => {
        #[pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1) -> PyResult<$ret> {
                $crate::macros::to_py_result(self.$inner.$method($arg1))
            }
        }
    };
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty, $arg2:ident : $ty2:ty) -> $ret:ty) => {
        #[pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1, $arg2: $ty2) -> PyResult<$ret> {
                $crate::macros::to_py_result(self.$inner.$method($arg1, $arg2))
            }
        }
    };
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty, $arg2:ident : $ty2:ty, $arg3:ident : $ty3:ty) -> $ret:ty) => {
        #[pymethods]
        impl $class {
            fn $method(&self, $arg1: $ty1, $arg2: $ty2, $arg3: $ty3) -> PyResult<$ret> {
                $crate::macros::to_py_result(self.$inner.$method($arg1, $arg2, $arg3))
            }
        }
    };
}

/// Generate a JSON wrapper method (returns serde_json::Value converted to PyObject)
macro_rules! pyo3_wrap_json {
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pymethods]
        impl $class {
            fn $method(&self, py: Python<'_>) -> PyResult<PyObject> {
                let value = $crate::macros::to_py_result(self.$inner.$method())?;
                $crate::macros::json_to_py(py, &value)
            }
        }
    };
    ($class:ty, $inner:ident, $method:ident($arg1:ident : $ty1:ty)) => {
        #[pymethods]
        impl $class {
            fn $method(&self, py: Python<'_>, $arg1: $ty1) -> PyResult<PyObject> {
                let value = $crate::macros::to_py_result(self.$inner.$method($arg1))?;
                $crate::macros::json_to_py(py, &value)
            }
        }
    };
}

/// Generate a JSON Vec wrapper method (returns Vec<serde_json::Value> converted to PyObject list)
macro_rules! pyo3_wrap_json_vec {
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pymethods]
        impl $class {
            fn $method(&self, py: Python<'_>) -> PyResult<PyObject> {
                let values = $crate::macros::to_py_result(self.$inner.$method())?;
                $crate::macros::json_vec_to_py(py, values)
            }
        }
    };
}

/// Generate a HashMap wrapper method (returns HashMap<String, String> converted to PyObject dict)
macro_rules! pyo3_wrap_hashmap {
    ($class:ty, $inner:ident, $method:ident()) => {
        #[pymethods]
        impl $class {
            fn $method(&self, py: Python<'_>) -> PyResult<PyObject> {
                let map = $crate::macros::to_py_result(self.$inner.$method())?;
                $crate::macros::hashmap_to_py(py, map)
            }
        }
    };
}

pub(crate) use pyo3_wrap;
pub(crate) use pyo3_wrap_json;
pub(crate) use pyo3_wrap_json_vec;
pub(crate) use pyo3_wrap_hashmap;
