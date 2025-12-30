use crate::error::{AssassinateError, Result};
use magnus::{
    class, embed, exception,
    value::{qnil, IntoId, ReprValue},
    IntoValue, RArray, RHash, RString, Ruby, Symbol, TryConvert, Value,
};
use std::mem;
use std::sync::Once;

static INIT: Once = Once::new();

// ========== Lazy Symbols for Common Method Names ==========
// LazyId provides thread-safe, lazily-initialized symbol IDs
// Use *sym::NAME to dereference and get the OpaqueId for funcall

/// Common Ruby method symbols used throughout the bridge
/// These are lazily initialized on first use and cached
pub mod sym {
    use magnus::value::LazyId;

    // Collection access
    pub static KEYS: LazyId = LazyId::new("keys");
    pub static LENGTH: LazyId = LazyId::new("length");
    pub static TO_A: LazyId = LazyId::new("to_a");
    pub static TO_S: LazyId = LazyId::new("to_s");
    pub static EACH: LazyId = LazyId::new("each");

    // Hash operations
    pub static AREF: LazyId = LazyId::new("[]");
    pub static ASET: LazyId = LazyId::new("[]=");
    pub static DELETE: LazyId = LazyId::new("delete");
    pub static FETCH: LazyId = LazyId::new("fetch");

    // Session methods
    pub static SESSIONS: LazyId = LazyId::new("sessions");
    pub static TYPE: LazyId = LazyId::new("type");
    pub static INFO: LazyId = LazyId::new("info");
    pub static ALIVE: LazyId = LazyId::new("alive?");
    pub static KILL: LazyId = LazyId::new("kill");
    pub static READ: LazyId = LazyId::new("read");
    pub static WRITE: LazyId = LazyId::new("write");
    pub static RUN_CMD: LazyId = LazyId::new("run_cmd");
    pub static SHELL_READ: LazyId = LazyId::new("shell_read");
    pub static SHELL_WRITE: LazyId = LazyId::new("shell_write");

    // Framework methods
    pub static MODULES: LazyId = LazyId::new("modules");
    pub static CREATE: LazyId = LazyId::new("create");
    pub static JOBS: LazyId = LazyId::new("jobs");
    pub static PLUGINS: LazyId = LazyId::new("plugins");
    pub static DB: LazyId = LazyId::new("db");
    pub static DATASTORE: LazyId = LazyId::new("datastore");
    pub static VERSION: LazyId = LazyId::new("version");
    pub static THREADS: LazyId = LazyId::new("threads");

    // Module methods
    pub static NAME: LazyId = LazyId::new("name");
    pub static FULLNAME: LazyId = LazyId::new("fullname");
    pub static DESCRIPTION: LazyId = LazyId::new("description");
    pub static RUN: LazyId = LazyId::new("run");
    pub static SETUP: LazyId = LazyId::new("setup");
    pub static CLEANUP: LazyId = LazyId::new("cleanup");
    pub static EXPLOIT: LazyId = LazyId::new("exploit");
    pub static CHECK: LazyId = LazyId::new("check");
    pub static OPTIONS: LazyId = LazyId::new("options");
    pub static VALIDATE: LazyId = LazyId::new("validate");
    pub static TARGETS: LazyId = LazyId::new("targets");
    pub static ACTIONS: LazyId = LazyId::new("actions");

    // Database methods
    pub static HOSTS: LazyId = LazyId::new("hosts");
    pub static SERVICES: LazyId = LazyId::new("services");
    pub static VULNS: LazyId = LazyId::new("vulns");
    pub static CREDS: LazyId = LazyId::new("creds");
    pub static LOOT: LazyId = LazyId::new("loot");
    pub static NOTES: LazyId = LazyId::new("notes");
    pub static WORKSPACES: LazyId = LazyId::new("workspaces");
    pub static WORKSPACE: LazyId = LazyId::new("workspace");

    // Filesystem methods
    pub static PWD: LazyId = LazyId::new("pwd");
    pub static CHDIR: LazyId = LazyId::new("chdir");
    pub static LS: LazyId = LazyId::new("ls");
    pub static MKDIR: LazyId = LazyId::new("mkdir");
    pub static RMDIR: LazyId = LazyId::new("rmdir");
    pub static STAT: LazyId = LazyId::new("stat");
    pub static FILE_EXIST: LazyId = LazyId::new("file?");
    pub static RM: LazyId = LazyId::new("rm");
    pub static MV: LazyId = LazyId::new("mv");
    pub static CP: LazyId = LazyId::new("cp");
    pub static DOWNLOAD: LazyId = LazyId::new("download");
    pub static UPLOAD: LazyId = LazyId::new("upload");

    // Process methods
    pub static GETPID: LazyId = LazyId::new("getpid");
    pub static PS: LazyId = LazyId::new("ps");

    // System methods
    pub static SYSINFO: LazyId = LazyId::new("sysinfo");
    pub static GETUID: LazyId = LazyId::new("getuid");
    pub static GETENV: LazyId = LazyId::new("getenv");

    // Object introspection
    pub static ID: LazyId = LazyId::new("id");
    pub static CLASS: LazyId = LazyId::new("class");
    pub static ADDRESS: LazyId = LazyId::new("address");
    pub static PORT: LazyId = LazyId::new("port");
    pub static PROTO: LazyId = LazyId::new("proto");
    pub static HOST: LazyId = LazyId::new("host");
    pub static DATA: LazyId = LazyId::new("data");
    pub static NTYPE: LazyId = LazyId::new("ntype");
    pub static CREATED_AT: LazyId = LazyId::new("created_at");

    // Transport methods
    pub static CORE: LazyId = LazyId::new("core");
    pub static TRANSPORT_LIST: LazyId = LazyId::new("transport_list");
    pub static TRANSPORT_ADD: LazyId = LazyId::new("transport_add");
    pub static TRANSPORT_REMOVE: LazyId = LazyId::new("transport_remove");
    pub static TRANSPORT_CHANGE: LazyId = LazyId::new("transport_change");
    pub static TRANSPORT_SLEEP: LazyId = LazyId::new("transport_sleep");
    pub static TRANSPORT_NEXT: LazyId = LazyId::new("transport_next");
    pub static TRANSPORT_PREV: LazyId = LazyId::new("transport_prev");
    pub static SET_TRANSPORT_TIMEOUTS: LazyId = LazyId::new("set_transport_timeouts");

    // Client core methods
    pub static MIGRATE: LazyId = LazyId::new("migrate");
    pub static USE: LazyId = LazyId::new("use");
    pub static SHUTDOWN: LazyId = LazyId::new("shutdown");
    pub static MACHINE_ID: LazyId = LazyId::new("machine_id");
    pub static NATIVE_ARCH: LazyId = LazyId::new("native_arch");
    pub static SESSION_GUID: LazyId = LazyId::new("session_guid");
    pub static SECURE: LazyId = LazyId::new("secure");

    // Meterpreter extensions
    pub static STDAPI: LazyId = LazyId::new("stdapi");
    pub static FS: LazyId = LazyId::new("fs");
    pub static SYS: LazyId = LazyId::new("sys");
    pub static NET: LazyId = LazyId::new("net");
    pub static CONFIG: LazyId = LazyId::new("config");
    pub static PROCESS: LazyId = LazyId::new("process");

    // Extension check
    pub static EXT: LazyId = LazyId::new("ext");
    pub static ALIASES: LazyId = LazyId::new("aliases");
    pub static HAS_KEY: LazyId = LazyId::new("has_key?");
}

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

// ========== Object Introspection (using Magnus built-ins) ==========

/// Check if a Ruby object responds to a method using Magnus's built-in respond_to()
/// This is more efficient than calling the Ruby respond_to? method
///
/// # Arguments
/// * `obj` - The Ruby object to check
/// * `method` - The method name to check for
/// * `include_private` - Whether to include private methods (usually false)
pub fn responds_to(obj: Value, method: &str, include_private: bool) -> bool {
    obj.respond_to(method, include_private).unwrap_or(false)
}

/// Check if a Ruby object responds to a method (public only)
/// Shorthand for responds_to(obj, method, false)
pub fn responds_to_public(obj: Value, method: &str) -> bool {
    responds_to(obj, method, false)
}

/// Check if a Ruby value is an instance of a specific class using Magnus is_kind_of()
/// This is more efficient than calling Ruby's is_a? method
///
/// # Arguments
/// * `obj` - The Ruby object to check
/// * `class` - The Ruby class to check against
pub fn is_kind_of<T: magnus::Module>(obj: Value, class: T) -> bool {
    obj.is_kind_of(class)
}

/// Check if value is a Ruby String
pub fn is_string(val: Value) -> bool {
    RString::from_value(val).is_some()
}

/// Check if value is a Ruby Array
pub fn is_array(val: Value) -> bool {
    RArray::from_value(val).is_some()
}

/// Check if value is a Ruby Hash
pub fn is_hash(val: Value) -> bool {
    RHash::from_value(val).is_some()
}

/// Check if value is a Ruby Integer
pub fn is_integer(val: Value) -> bool {
    i64::try_convert(val).is_ok()
}

/// Check if value is a Ruby Float
pub fn is_float(val: Value) -> bool {
    f64::try_convert(val).is_ok()
}

/// Get the class of a Ruby object using Magnus class accessor
pub fn get_class(val: Value) -> Result<Value> {
    val.funcall(*sym::CLASS, ()).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to get class: {}", e))
    })
}

/// Get the class name of a Ruby object
pub fn class_name(val: Value) -> Result<String> {
    let cls = get_class(val)?;
    value_to_string(cls.funcall(*sym::NAME, ()).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to get class name: {}", e))
    })?)
}

// ========== Protected Calls (Exception Safety) ==========

/// Execute a closure with Ruby exception protection
/// Returns Err with the exception message if an exception is raised
pub fn protect<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> std::result::Result<T, magnus::Error>,
{
    match f() {
        Ok(v) => Ok(v),
        Err(e) => Err(AssassinateError::RubyError(e.to_string())),
    }
}

/// Call a method with exception protection
/// Catches Ruby exceptions and converts them to our Result type
pub fn safe_call<A>(obj: Value, method: &str, args: A) -> Result<Value>
where
    A: magnus::ArgList,
{
    obj.funcall(method, args).map_err(|e| {
        AssassinateError::RubyError(format!("Method '{}' failed: {}", method, e))
    })
}

/// Call a method with symbol (more efficient for repeated calls)
pub fn call_sym<S, A>(obj: Value, method: S, args: A) -> Result<Value>
where
    S: IntoId,
    A: magnus::ArgList,
{
    obj.funcall(method, args).map_err(|e| {
        AssassinateError::RubyError(format!("Method call failed: {}", e))
    })
}

// ========== Exception Class Accessors ==========

/// Get Ruby's StandardError exception class
pub fn standard_error() -> magnus::ExceptionClass {
    exception::standard_error()
}

/// Get Ruby's RuntimeError exception class
pub fn runtime_error() -> magnus::ExceptionClass {
    exception::runtime_error()
}

/// Get Ruby's ArgumentError exception class
pub fn arg_error() -> magnus::ExceptionClass {
    exception::arg_error()
}

/// Get Ruby's TypeError exception class
pub fn type_error() -> magnus::ExceptionClass {
    exception::type_error()
}

/// Get Ruby's IOError exception class
pub fn io_error() -> magnus::ExceptionClass {
    exception::io_error()
}

/// Get Ruby's SystemCallError exception class
pub fn system_call_error() -> magnus::ExceptionClass {
    exception::system_call_error()
}

/// Get Ruby's NoMethodError exception class
pub fn no_method_error() -> magnus::ExceptionClass {
    exception::no_method_error()
}

// ========== Built-in Class Accessors ==========

/// Get Ruby's String class
pub fn string_class() -> magnus::RClass {
    class::string()
}

/// Get Ruby's Array class
pub fn array_class() -> magnus::RClass {
    class::array()
}

/// Get Ruby's Hash class
pub fn hash_class() -> magnus::RClass {
    class::hash()
}

/// Get Ruby's Integer class
pub fn integer_class() -> magnus::RClass {
    class::integer()
}

/// Get Ruby's Float class
pub fn float_class() -> magnus::RClass {
    class::float()
}

/// Get Ruby's NilClass
pub fn nil_class() -> magnus::RClass {
    class::nil_class()
}

/// Get Ruby's TrueClass
pub fn true_class() -> magnus::RClass {
    class::true_class()
}

/// Get Ruby's FalseClass
pub fn false_class() -> magnus::RClass {
    class::false_class()
}

// ========== Symbol Creation ==========

/// Create a dynamic Ruby Symbol
/// Use StaticSymbol for symbols known at compile time
pub fn make_symbol(name: &str) -> Result<Symbol> {
    // Ensure Ruby is initialized
    let _ = get_ruby()?;
    Ok(Symbol::new(name))
}

/// Create a Ruby Symbol value
pub fn symbol_value(name: &str) -> Result<Value> {
    Ok(Symbol::new(name).as_value())
}

// ========== Array Creation and Manipulation ==========

/// Create a new empty Ruby array
pub fn new_ruby_array() -> Result<RArray> {
    let ruby = get_ruby()?;
    Ok(ruby.ary_new())
}

/// Create a Ruby array with pre-allocated capacity
pub fn new_ruby_array_with_capacity(capacity: usize) -> Result<RArray> {
    let ruby = get_ruby()?;
    Ok(ruby.ary_new_capa(capacity))
}

/// Create a Ruby array from an iterator
pub fn array_from_iter<I, T>(iter: I) -> Result<RArray>
where
    I: IntoIterator<Item = T>,
    T: IntoValue,
{
    let ruby = get_ruby()?;
    let arr = ruby.ary_new();
    for item in iter {
        arr.push(item).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to push to array: {}", e))
        })?;
    }
    Ok(arr)
}

/// Create a Ruby array of strings from a Rust Vec<String>
pub fn strings_to_ruby_array(strings: Vec<String>) -> Result<RArray> {
    array_from_iter(strings)
}

/// Create a Ruby array of integers from a Rust Vec<i64>
pub fn ints_to_ruby_array(ints: Vec<i64>) -> Result<RArray> {
    array_from_iter(ints)
}

// ========== Hash Creation ==========

/// Create a Ruby hash from key-value pairs iterator
pub fn hash_from_iter<I, K, V>(iter: I) -> Result<RHash>
where
    I: IntoIterator<Item = (K, V)>,
    K: IntoValue,
    V: IntoValue,
{
    let ruby = get_ruby()?;
    let hash = ruby.hash_new();
    for (key, value) in iter {
        hash.aset(key, value).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set hash entry: {}", e))
        })?;
    }
    Ok(hash)
}

/// Create a Ruby hash from a HashMap<String, String>
pub fn hashmap_to_ruby_hash(map: std::collections::HashMap<String, String>) -> Result<RHash> {
    hash_from_iter(map)
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
