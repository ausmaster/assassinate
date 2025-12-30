use crate::error::{AssassinateError, Result};
use magnus::{
    embed,
    value::{qnil, ReprValue},
    IntoValue, RArray, RHash, RString, Ruby, TryConvert, Value,
};
use std::mem;
use std::sync::Once;

static INIT: Once = Once::new();

// ========== Ruby VM Initialization ==========

/// Initialize the Ruby interpreter using Magnus embed
pub fn init_ruby() -> Result<()> {
    INIT.call_once(|| {
        unsafe {
            // Use Magnus embed::init for proper Ruby VM initialization
            // This ensures all stdlib methods (Dir.glob, Time.now, etc.) are available
            let guard = embed::init();

            // Prevent the guard from being dropped using mem::forget
            // This keeps the Ruby VM alive for the lifetime of the process
            mem::forget(guard);
        }

        // Verify stdlib methods are available
        if let Ok(ruby) = Ruby::get() {
            let code = r###"
                # Verify stdlib methods are available
                Time.now
                Dir.pwd
            "###;
            let _ = ruby.eval::<Value>(code);
        }
    });
    Ok(())
}

/// Get the Ruby VM handle
pub fn get_ruby() -> Result<Ruby> {
    init_ruby()?;
    Ruby::get().map_err(|e| {
        AssassinateError::RubyInitError(format!("Failed to get Ruby VM reference: {}", e))
    })
}

// ========== Metasploit Framework Initialization ==========

/// Initialize Metasploit Framework
pub fn init_metasploit(msf_path: &str) -> Result<Value> {
    let ruby = get_ruby()?;

    // Initialize Metasploit the same way msfconsole does
    let code = format!(
        r###"
        Dir.chdir('{}')
        ENV['BUNDLE_GEMFILE'] = '{}/Gemfile'
        $LOAD_PATH.unshift('{}/lib')
        ENV['RAILS_ENV'] ||= 'production'
        require '{}/config/boot'
        require 'msfenv'
        "###,
        msf_path, msf_path, msf_path, msf_path
    );

    ruby.eval::<Value>(&code)
        .map_err(|e| AssassinateError::RubyInitError(e.to_string()))?;

    Ok(qnil().as_value())
}

/// Create a new Metasploit Framework instance
pub fn create_framework(options: Option<serde_json::Value>) -> Result<Value> {
    let ruby = get_ruby()?;

    let code = if let Some(opts) = options {
        format!(
            r#"
            opts = {}
            Msf::Simple::Framework.create(opts)
            "#,
            serde_json::to_string(&opts).unwrap_or_else(|_| "{}".to_string())
        )
    } else {
        r#"Msf::Simple::Framework.create"#.to_string()
    };

    ruby.eval(&code)
        .map_err(|e| AssassinateError::RubyError(e.to_string()))
}

// ========== Ruby Method Calls ==========

/// Evaluate Ruby code and return the result
/// NOTE: This is intentionally using Ruby eval to interact with Metasploit Framework
#[allow(dead_code)]
pub fn eval_ruby(code: &str) -> Result<Value> {
    let ruby = get_ruby()?;
    ruby.eval::<Value>(code)
        .map_err(|e| AssassinateError::RubyError(e.to_string()))
}

/// Call a Ruby method on an object
/// Uses Magnus's built-in funcall method
pub fn call_method(obj: Value, method_name: &str, args: &[Value]) -> Result<Value> {
    obj.funcall(method_name, args).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to call method '{}': {}", method_name, e))
    })
}

// ========== Type Conversions (using Magnus TryConvert) ==========

/// Convert Ruby value to String using Magnus TryConvert
pub fn value_to_string(val: Value) -> Result<String> {
    // First try direct string conversion
    if let Some(rstring) = RString::from_value(val) {
        return rstring.to_string().map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to convert RString: {}", e))
        });
    }

    // Fall back to calling to_s
    let str_val: Value = val.funcall("to_s", ()).map_err(|e| {
        AssassinateError::ConversionError(format!("Failed to call to_s: {}", e))
    })?;

    TryConvert::try_convert(str_val).map_err(|e: magnus::Error| {
        AssassinateError::ConversionError(format!("Failed to convert to string: {}", e))
    })
}

/// Convert Ruby value to i64 using Magnus TryConvert
pub fn value_to_i64(val: Value) -> Result<i64> {
    TryConvert::try_convert(val).map_err(|e: magnus::Error| {
        AssassinateError::ConversionError(format!("Failed to convert to i64: {}", e))
    })
}

/// Convert Ruby Hash to JSON
/// Uses Magnus RHash iteration for efficiency
pub fn hash_to_json(hash: Value) -> Result<serde_json::Value> {
    // Try to convert to RHash for direct access
    if let Some(rhash) = RHash::from_value(hash) {
        let mut map = serde_json::Map::new();

        // Use foreach to iterate over hash entries
        rhash
            .foreach(|key: Value, value: Value| {
                let key_str = value_to_string(key).unwrap_or_else(|_| "unknown".to_string());
                let json_val = ruby_value_to_json(value);
                map.insert(key_str, json_val);
                Ok(magnus::r_hash::ForEach::Continue)
            })
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to iterate hash: {}", e))
            })?;

        return Ok(serde_json::Value::Object(map));
    }

    // Fallback to Ruby JSON generation for non-standard hash objects
    let ruby = get_ruby()?;
    let json_val: Value = ruby
        .eval::<Value>(&format!("require 'json'; JSON.generate({:?})", hash))
        .map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to convert Hash to JSON: {}", e))
        })?;

    let json_str: String = TryConvert::try_convert(json_val).map_err(|e: magnus::Error| {
        AssassinateError::ConversionError(format!("Failed to parse JSON string: {}", e))
    })?;

    serde_json::from_str(&json_str)
        .map_err(|e| AssassinateError::ConversionError(format!("Failed to parse JSON: {}", e)))
}

/// Convert a Ruby value to a serde_json::Value
fn ruby_value_to_json(val: Value) -> serde_json::Value {
    if val.is_nil() {
        return serde_json::Value::Null;
    }

    // Try integer
    if let Ok(i) = i64::try_convert(val) {
        return serde_json::Value::Number(i.into());
    }

    // Try float
    if let Ok(f) = f64::try_convert(val) {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return serde_json::Value::Number(n);
        }
    }

    // Try bool - check for true/false specifically
    if let Ok(b) = bool::try_convert(val) {
        return serde_json::Value::Bool(b);
    }

    // Try string
    if let Ok(s) = value_to_string(val) {
        return serde_json::Value::String(s);
    }

    // Try array
    if let Some(arr) = RArray::from_value(val) {
        let vec: Vec<serde_json::Value> = (0..arr.len())
            .filter_map(|i| arr.entry::<Value>(i as isize).ok())
            .map(ruby_value_to_json)
            .collect();
        return serde_json::Value::Array(vec);
    }

    // Try hash
    if let Some(hash) = RHash::from_value(val) {
        let mut map = serde_json::Map::new();
        let _ = hash.foreach(|k: Value, v: Value| {
            let key = value_to_string(k).unwrap_or_else(|_| "unknown".to_string());
            map.insert(key, ruby_value_to_json(v));
            Ok(magnus::r_hash::ForEach::Continue)
        });
        return serde_json::Value::Object(map);
    }

    // Fallback to string representation
    value_to_string(val)
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null)
}

// ========== Ruby Value Creation ==========

/// Convert Rust string to Ruby String value
pub fn to_ruby_str(s: &str) -> Result<Value> {
    let ruby = get_ruby()?;
    Ok(ruby.str_new(s).as_value())
}

/// Convert Rust i64 to Ruby Integer value
pub fn to_ruby_int(i: i64) -> Result<Value> {
    let ruby = get_ruby()?;
    Ok(ruby.integer_from_i64(i).as_value())
}

// ========== Ruby Array Operations (using Magnus RArray) ==========

/// Get the length of a Ruby array using Magnus RArray::len()
pub fn ruby_array_len(array: Value) -> Result<usize> {
    if let Some(rarray) = RArray::from_value(array) {
        Ok(rarray.len())
    } else {
        // Fallback for array-like objects
        let len_val = call_method(array, "length", &[])?;
        TryConvert::try_convert(len_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to get array length: {}", e))
        })
    }
}

/// Get an element from a Ruby array by index using Magnus RArray::entry()
pub fn ruby_array_get(array: Value, index: usize) -> Result<Value> {
    if let Some(rarray) = RArray::from_value(array) {
        rarray.entry(index as isize).map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to get array element: {}", e))
        })
    } else {
        // Fallback for array-like objects
        let idx_val = to_ruby_int(index as i64)?;
        call_method(array, "[]", &[idx_val])
    }
}

/// Convert Ruby array to Vec<String> using Magnus RArray
pub fn ruby_array_to_strings(array: Value) -> Result<Vec<String>> {
    if let Some(rarray) = RArray::from_value(array) {
        let len = rarray.len();
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let elem: Value = rarray.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get element {}: {}", i, e))
            })?;
            result.push(value_to_string(elem)?);
        }
        Ok(result)
    } else {
        // Fallback
        let len = ruby_array_len(array)?;
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let elem = ruby_array_get(array, i)?;
            result.push(value_to_string(elem)?);
        }
        Ok(result)
    }
}

/// Convert Ruby array to Vec<i64> using Magnus RArray
pub fn ruby_array_to_ints(array: Value) -> Result<Vec<i64>> {
    if let Some(rarray) = RArray::from_value(array) {
        let len = rarray.len();
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let val: i64 = rarray.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!(
                    "Failed to get int element {}: {}",
                    i, e
                ))
            })?;
            result.push(val);
        }
        Ok(result)
    } else {
        // Fallback
        let len = ruby_array_len(array)?;
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let elem = ruby_array_get(array, i)?;
            let val: i64 = TryConvert::try_convert(elem).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert array element to i64: {}",
                    e
                ))
            })?;
            result.push(val);
        }
        Ok(result)
    }
}

/// Iterate over Ruby array with callback, extracting a string property from each element
pub fn ruby_array_map_property(array: Value, property: &str) -> Result<Vec<String>> {
    let len = ruby_array_len(array)?;
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        let elem = ruby_array_get(array, i)?;
        let prop_val = call_method(elem, property, &[])?;
        result.push(value_to_string(prop_val)?);
    }
    Ok(result)
}

// ========== Simple Getter Helpers ==========

/// Call a method on a Ruby object and convert result to String
pub fn get_string_attr(obj: Value, method: &str) -> Result<String> {
    let val = call_method(obj, method, &[])?;
    value_to_string(val)
}

/// Call a method on a Ruby object and convert result to bool
/// Uses Magnus's to_bool() which follows Ruby semantics
pub fn get_bool_attr(obj: Value, method: &str) -> Result<bool> {
    let val = call_method(obj, method, &[])?;
    Ok(val.to_bool())
}

/// Call a method on a Ruby object and convert result to i64
pub fn get_i64_attr(obj: Value, method: &str) -> Result<i64> {
    let val = call_method(obj, method, &[])?;
    value_to_i64(val)
}

/// Call a method on a Ruby object with one string arg, return nothing
pub fn call_void_with_str(obj: Value, method: &str, arg: &str) -> Result<()> {
    call_method(obj, method, &[to_ruby_str(arg)?])?;
    Ok(())
}

/// Call a method on a Ruby object with one string arg, return String
pub fn call_str_with_str(obj: Value, method: &str, arg: &str) -> Result<String> {
    let val = call_method(obj, method, &[to_ruby_str(arg)?])?;
    value_to_string(val)
}

/// Call a method on a Ruby object with one string arg, return bool
pub fn call_bool_with_str(obj: Value, method: &str, arg: &str) -> Result<bool> {
    let val = call_method(obj, method, &[to_ruby_str(arg)?])?;
    Ok(val.to_bool())
}

/// Call a method on a Ruby object with one string arg, return Vec<String>
pub fn call_strings_with_str(obj: Value, method: &str, arg: &str) -> Result<Vec<String>> {
    let val = call_method(obj, method, &[to_ruby_str(arg)?])?;
    ruby_array_to_strings(val)
}

// ========== Ruby Hash Operations (using Magnus RHash) ==========

/// Build a Ruby options hash with Quiet mode set and optional additional options
/// Uses Magnus RHash::aset() for direct hash manipulation
pub fn build_quiet_opts(
    options: Option<std::collections::HashMap<String, String>>,
) -> Result<Value> {
    let ruby = get_ruby()?;
    let hash = ruby.hash_new();

    // Set Quiet mode using RHash::aset
    hash.aset("Quiet", true).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to set Quiet option: {}", e))
    })?;

    // Set additional options
    if let Some(opts_map) = options {
        for (key, value) in opts_map {
            hash.aset(key, value).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }
    }

    Ok(hash.as_value())
}

/// Build a Ruby options hash from a HashMap (without Quiet mode)
/// Uses Magnus RHash::aset() for direct hash manipulation
pub fn build_opts(options: Option<std::collections::HashMap<String, String>>) -> Result<Value> {
    let ruby = get_ruby()?;
    let hash = ruby.hash_new();

    if let Some(opts_map) = options {
        for (key, value) in opts_map {
            hash.aset(key, value).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }
    }

    Ok(hash.as_value())
}

/// Create a new Ruby hash and return it as RHash
pub fn new_ruby_hash() -> Result<RHash> {
    let ruby = get_ruby()?;
    Ok(ruby.hash_new())
}

/// Set a key-value pair on a Ruby hash using Magnus RHash::aset()
pub fn hash_set<K: IntoValue, V: IntoValue>(hash: RHash, key: K, value: V) -> Result<()> {
    hash.aset(key, value).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to set hash key: {}", e))
    })
}

/// Get a value from a Ruby hash using Magnus RHash::aref()
pub fn hash_get<K: IntoValue, V: TryConvert>(hash: RHash, key: K) -> Result<V> {
    hash.aref(key).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to get hash key: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_ruby() {
        assert!(init_ruby().is_ok());
    }

    #[test]
    fn test_eval_ruby() {
        let _ = init_ruby();
        if let Ok(result) = eval_ruby("1 + 1") {
            assert_eq!(value_to_i64(result).unwrap(), 2);
        }
    }

    #[test]
    fn test_value_conversions() {
        let _ = init_ruby();

        if let Ok(int_val) = eval_ruby("42") {
            assert_eq!(value_to_i64(int_val).unwrap(), 42);
        }

        if let Ok(str_val) = eval_ruby("'hello'") {
            assert_eq!(value_to_string(str_val).unwrap(), "hello");
        }
    }

    #[test]
    fn test_is_nil() {
        let _ = init_ruby();

        if let Ok(nil_val) = eval_ruby("nil") {
            assert!(nil_val.is_nil());
        }

        if let Ok(not_nil) = eval_ruby("42") {
            assert!(!not_nil.is_nil());
        }
    }

    #[test]
    fn test_to_bool() {
        let _ = init_ruby();

        // nil is falsy
        if let Ok(nil_val) = eval_ruby("nil") {
            assert!(!nil_val.to_bool());
        }

        // false is falsy
        if let Ok(false_val) = eval_ruby("false") {
            assert!(!false_val.to_bool());
        }

        // true is truthy
        if let Ok(true_val) = eval_ruby("true") {
            assert!(true_val.to_bool());
        }

        // 0 is truthy in Ruby!
        if let Ok(zero_val) = eval_ruby("0") {
            assert!(zero_val.to_bool());
        }

        // empty string is truthy
        if let Ok(empty_str) = eval_ruby("''") {
            assert!(empty_str.to_bool());
        }
    }

    #[test]
    fn test_ruby_array() {
        let _ = init_ruby();

        if let Ok(arr) = eval_ruby("[1, 2, 3]") {
            assert_eq!(ruby_array_len(arr).unwrap(), 3);
            assert_eq!(value_to_i64(ruby_array_get(arr, 0).unwrap()).unwrap(), 1);
            assert_eq!(ruby_array_to_ints(arr).unwrap(), vec![1, 2, 3]);
        }
    }

    #[test]
    fn test_ruby_hash() {
        let _ = init_ruby();

        if let Ok(ruby) = get_ruby() {
            let hash = ruby.hash_new();
            hash.aset("foo", 42).unwrap();

            let val: i64 = hash.aref("foo").unwrap();
            assert_eq!(val, 42);
        }
    }
}
