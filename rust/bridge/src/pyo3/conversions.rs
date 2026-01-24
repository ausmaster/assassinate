//! Type conversion utilities for Pyo3
//!
//! This module provides functions for converting Rust types to Python objects,
//! particularly for complex types like `serde_json::Value` and `HashMap`.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::ToPyObject;
use std::collections::HashMap;

/// Convert a `serde_json::Value` to a Python object
///
/// Maps JSON types to Python equivalents:
/// - `null` -> `None`
/// - `bool` -> `bool`
/// - `number` -> `int` or `float`
/// - `string` -> `str`
/// - `array` -> `list`
/// - `object` -> `dict`
pub fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
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

/// Convert a `Vec<serde_json::Value>` to a Python list
pub fn json_vec_to_py(py: Python<'_>, values: Vec<serde_json::Value>) -> PyResult<PyObject> {
    let list = PyList::empty_bound(py);
    for value in values {
        list.append(json_to_py(py, &value)?)?;
    }
    Ok(list.into())
}

/// Convert a `HashMap<String, String>` to a Python dict
pub fn hashmap_to_py(
    py: Python<'_>,
    map: HashMap<String, String>,
) -> PyResult<PyObject> {
    let dict = PyDict::new_bound(py);
    for (k, v) in map {
        dict.set_item(k, v)?;
    }
    Ok(dict.into())
}
