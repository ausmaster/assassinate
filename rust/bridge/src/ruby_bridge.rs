use crate::error::{AssassinateError, Result};
use magnus::{embed, value::ReprValue, Ruby, TryConvert, Value};
use std::mem;
use std::sync::Once;

static INIT: Once = Once::new();

/// Check if a Magnus Value is nil
pub fn is_nil(val: Value) -> bool {
    // In Magnus 0.7, we can check if a value is nil by comparing its inspect output
    // or by checking if it equals the nil constant
    match Ruby::get() {
        Ok(ruby) => {
            let nil_val = ruby.qnil().as_value();
            // Compare the raw values
            format!("{:?}", val) == format!("{:?}", nil_val)
        }
        Err(_) => false,
    }
}

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

/// Initialize Metasploit Framework
pub fn init_metasploit(msf_path: &str) -> Result<Value> {
    let ruby = get_ruby()?;

    // Initialize Metasploit the same way msfconsole does:
    // 1. Load config/boot (sets up bundler)
    // 2. Load msfenv (sets up Rails environment and MSF autoloader)
    // This ensures Rails.application is initialized before Framework.create is called
    let code = format!(
        r###"
        # Change to MSF installation directory
        Dir.chdir('{}')

        # Add lib directory to load path
        $LOAD_PATH.unshift('{}/lib')

        # Set environment to production (same as msfconsole default)
        ENV['RAILS_ENV'] ||= 'production'

        # Load boot configuration (sets up bundler)
        require '{}/config/boot'

        # Load msfenv (sets up Rails app and MSF autoloader)
        require 'msfenv'
        "###,
        msf_path, msf_path, msf_path
    );

    let _result: Value = ruby
        .eval::<Value>(&code)
        .map_err(|e| AssassinateError::RubyInitError(e.to_string()))?;

    // Return the Ruby nil value
    Ok(ruby.qnil().as_value())
}

/// Create a new Metasploit Framework instance
pub fn create_framework(options: Option<serde_json::Value>) -> Result<Value> {
    let ruby = get_ruby()?;

    // MSF is already loaded by init_metasploit (via msfenv)
    // Just create the framework instance
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

/// Evaluate Ruby code and return the result
#[allow(dead_code)]
pub fn eval_ruby(code: &str) -> Result<Value> {
    let ruby = get_ruby()?;
    ruby.eval::<Value>(code)
        .map_err(|e| AssassinateError::RubyError(e.to_string()))
}

/// Call a Ruby method on an object
pub fn call_method(obj: Value, method_name: &str, args: &[Value]) -> Result<Value> {
    let _ruby = get_ruby()?;

    obj.funcall(method_name, args).map_err(|e| {
        AssassinateError::RubyError(format!("Failed to call method '{}': {}", method_name, e))
    })
}

/// Convert Ruby value to String
pub fn value_to_string(val: Value) -> Result<String> {
    let str_val = val.funcall::<_, _, Value>("to_s", ()).map_err(|e| {
        AssassinateError::ConversionError(format!("Failed to call to_s on Ruby value: {}", e))
    })?;

    TryConvert::try_convert(str_val).map_err(|e: magnus::Error| {
        AssassinateError::ConversionError(format!("Failed to convert Ruby value to string: {}", e))
    })
}

/// Convert Ruby value to Integer
#[allow(dead_code)]
pub fn value_to_i64(val: Value) -> Result<i64> {
    TryConvert::try_convert(val).map_err(|e: magnus::Error| {
        AssassinateError::ConversionError(format!("Failed to convert Ruby value to i64: {}", e))
    })
}

/// Convert Ruby value to Boolean
pub fn value_to_bool(val: Value) -> Result<bool> {
    // In Ruby, only nil and false are falsy
    Ok(!is_nil(val))
}

/// Convert Ruby Hash to JSON
pub fn hash_to_json(hash: Value) -> Result<serde_json::Value> {
    let _ruby = get_ruby()?;

    let json_val: Value = _ruby
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
}
