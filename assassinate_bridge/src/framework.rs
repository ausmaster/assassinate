//! Framework types and operations for Metasploit Framework interaction

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, create_framework, is_nil, value_to_string};
use magnus::{value::ReprValue, TryConvert, Value};
use std::collections::HashMap;

// Only import PyO3 types when python-bindings feature is enabled
#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;

/// Core Metasploit Framework interface
///
/// This type provides access to the Metasploit Framework functionality through Ruby FFI.
#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct Framework {
    pub(crate) ruby_framework: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl Framework {
    #[cfg_attr(feature = "python-bindings", new)]
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (options=None)))]
    pub fn new(options: Option<HashMap<String, String>>) -> Result<Self> {
        let opts_json = options.and_then(|o| serde_json::to_value(o).ok());

        let ruby_framework = create_framework(opts_json)?;

        Ok(Framework { ruby_framework })
    }

    /// Get the Metasploit Framework version
    pub fn version(&self) -> Result<String> {
        let version_val = call_method(self.ruby_framework, "version", &[])?;
        Ok(value_to_string(version_val)?)
    }

    /// List all module reference names for a given type
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (module_type)))]
    pub fn list_modules(&self, module_type: &str) -> Result<Vec<String>> {
        let modules_manager = call_method(self.ruby_framework, "modules", &[])?;

        let module_set = call_method(modules_manager, module_type, &[])?;

        let module_refnames = call_method(module_set, "module_refnames", &[])?;

        // Convert Ruby Array to Rust Vec<String>
        let refnames: Vec<String> =
            TryConvert::try_convert(module_refnames).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert module refnames to Vec<String>: {}",
                    e
                ))
            })?;

        Ok(refnames)
    }

    /// Create a module instance by name
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (module_name)))]
    pub fn create_module(&self, module_name: &str) -> Result<Module> {
        let modules_manager = call_method(self.ruby_framework, "modules", &[])?;

        let name_val = crate::ruby_bridge::get_ruby()?
            .str_new(module_name)
            .as_value();

        let module_instance = call_method(modules_manager, "create", &[name_val])?;

        // Check if module is nil
        if is_nil(module_instance) {
            return Err(AssassinateError::ModuleNotFound(module_name.to_string()));
        }

        Ok(Module {
            ruby_module: module_instance,
        })
    }

    /// Get the sessions manager
    pub fn sessions(&self) -> Result<SessionManager> {
        let sessions_val = call_method(self.ruby_framework, "sessions", &[])?;

        Ok(SessionManager {
            ruby_sessions: sessions_val,
        })
    }

    /// Get the datastore
    pub fn datastore(&self) -> Result<DataStore> {
        let datastore_val = call_method(self.ruby_framework, "datastore", &[])?;

        Ok(DataStore {
            ruby_datastore: datastore_val,
        })
    }

    #[cfg(feature = "python-bindings")]
    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<Framework version={}>", self.version()?))
    }
}

/// Metasploit module instance
#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct Module {
    pub(crate) ruby_module: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl Module {
    /// Get module name
    pub fn name(&self) -> Result<String> {
        let name_val = call_method(self.ruby_module, "name", &[])?;
        Ok(value_to_string(name_val)?)
    }

    /// Get module full name
    pub fn fullname(&self) -> Result<String> {
        let fullname_val = call_method(self.ruby_module, "fullname", &[])?;
        Ok(value_to_string(fullname_val)?)
    }

    /// Get module description
    pub fn description(&self) -> Result<String> {
        let desc_val = call_method(self.ruby_module, "description", &[])?;
        Ok(value_to_string(desc_val)?)
    }

    /// Get module type
    pub fn module_type(&self) -> Result<String> {
        let type_val = call_method(self.ruby_module, "type", &[])?;
        Ok(value_to_string(type_val)?)
    }

    /// Get module datastore
    pub fn datastore(&self) -> Result<DataStore> {
        let datastore_val = call_method(self.ruby_module, "datastore", &[])?;

        Ok(DataStore {
            ruby_datastore: datastore_val,
        })
    }

    /// Set a datastore option
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (key, value)))]
    pub fn set_option(&self, key: &str, value: &str) -> Result<()> {
        let datastore = self.datastore()?;
        datastore.set(key, value)?;
        Ok(())
    }

    /// Get a datastore option
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (key)))]
    pub fn get_option(&self, key: &str) -> Result<Option<String>> {
        let datastore = self.datastore()?;
        datastore.get(key)
    }

    /// Validate module configuration
    pub fn validate(&self) -> Result<bool> {
        let result = call_method(self.ruby_module, "validate", &[]);

        match result {
            Ok(_) => Ok(true),
            Err(e) => Err(AssassinateError::ModuleValidationError(e.to_string()).into()),
        }
    }

    /// Run an exploit module
    /// Returns the session ID if successful, None otherwise
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (payload, **options)))]
    pub fn exploit(
        &self,
        payload: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<Option<i64>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash in Ruby
        let opts_val = ruby.hash_new().as_value();

        // Set payload
        let payload_key = ruby.str_new("Payload").as_value();
        let payload_val = ruby.str_new(payload).as_value();
        call_method(opts_val, "[]=", &[payload_key, payload_val])?;

        // Set Quiet mode
        let quiet_key = ruby.str_new("Quiet").as_value();
        let quiet_val = ruby.qtrue().as_value();
        call_method(opts_val, "[]=", &[quiet_key, quiet_val])?;

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        // Call exploit_simple on the module
        let session_val = call_method(self.ruby_module, "exploit_simple", &[opts_val])?;

        if is_nil(session_val) {
            Ok(None)
        } else {
            // Get session ID
            let sid_val = call_method(session_val, "sid", &[])?;
            let session_id: i64 =
                TryConvert::try_convert(sid_val).map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!(
                        "Failed to convert session ID: {}",
                        e
                    ))
                })?;
            Ok(Some(session_id))
        }
    }

    /// Run an auxiliary module
    /// Returns true if successful, false otherwise
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (**options)))]
    pub fn run(&self, options: Option<HashMap<String, String>>) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash in Ruby
        let opts_val = ruby.hash_new().as_value();

        // Set Quiet mode
        let quiet_key = ruby.str_new("Quiet").as_value();
        let quiet_val = ruby.qtrue().as_value();
        call_method(opts_val, "[]=", &[quiet_key, quiet_val])?;

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        // Call run_simple on the module
        match call_method(self.ruby_module, "run_simple", &[opts_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if target is vulnerable
    /// Returns check result code as string
    pub fn check(&self) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash in Ruby
        let opts_val = ruby.hash_new().as_value();

        // Set Quiet mode
        let quiet_key = ruby.str_new("Quiet").as_value();
        let quiet_val = ruby.qtrue().as_value();
        call_method(opts_val, "[]=", &[quiet_key, quiet_val])?;

        // Call check_simple on the module
        match call_method(self.ruby_module, "check_simple", &[opts_val]) {
            Ok(result) => Ok(value_to_string(result)?),
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("NotImplementedError") || err_msg.contains("Unsupported") {
                    Ok("Unsupported".to_string())
                } else {
                    Ok("Unknown".to_string())
                }
            }
        }
    }

    /// Check if module has check method
    pub fn has_check(&self) -> Result<bool> {
        let result = call_method(self.ruby_module, "has_check?", &[])?;
        Ok(crate::ruby_bridge::value_to_bool(result)?)
    }

    /// Get available payloads for this exploit
    pub fn compatible_payloads(&self) -> Result<Vec<String>> {
        // Check if module responds to compatible_payloads
        let ruby = crate::ruby_bridge::get_ruby()?;
        let method_name = ruby.str_new("compatible_payloads").as_value();

        match call_method(self.ruby_module, "respond_to?", &[method_name]) {
            Ok(responds) if crate::ruby_bridge::value_to_bool(responds)? => {
                // Get compatible payloads
                match call_method(self.ruby_module, "compatible_payloads", &[]) {
                    Ok(payloads_val) => {
                        // Set payloads_array variable
                        ruby.eval::<Value>(&format!("$temp_payloads = {:?}", payloads_val))
                            .ok();

                        // For now, return empty if we can't easily extract
                        Ok(vec![])
                    }
                    Err(_) => Ok(vec![]),
                }
            }
            _ => Ok(vec![]),
        }
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Module name='{}' type='{}'>",
            self.fullname()?,
            self.module_type()?
        ))
    }
}

#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct DataStore {
    pub(crate) ruby_datastore: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl DataStore {
    /// Set a value in the datastore
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (key, value)))]
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        let key_val = crate::ruby_bridge::get_ruby()?.str_new(key).as_value();
        let value_val = crate::ruby_bridge::get_ruby()?.str_new(value).as_value();

        call_method(self.ruby_datastore, "[]=", &[key_val, value_val])?;

        Ok(())
    }

    /// Get a value from the datastore
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (key)))]
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let key_val = crate::ruby_bridge::get_ruby()?.str_new(key).as_value();

        let result = call_method(self.ruby_datastore, "[]", &[key_val])?;

        // Check if nil
        if is_nil(result) {
            Ok(None)
        } else {
            Ok(Some(value_to_string(result)?))
        }
    }

    /// Convert datastore to dict
    pub fn to_dict(&self) -> Result<HashMap<String, String>> {
        let hash_val = call_method(self.ruby_datastore, "to_h", &[])?;

        let json = crate::ruby_bridge::hash_to_json(hash_val)?;

        let dict: HashMap<String, String> = serde_json::from_value(json).map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to convert datastore to dict: {}", e))
        })?;

        Ok(dict)
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<DataStore {}>", self.to_dict()?.len()))
    }
}

#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct SessionManager {
    pub(crate) ruby_sessions: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl SessionManager {
    /// List all session IDs
    pub fn list(&self) -> Result<Vec<i64>> {
        let keys_val = call_method(self.ruby_sessions, "keys", &[])?;

        let session_ids: Vec<i64> =
            TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert session IDs: {}", e))
            })?;

        Ok(session_ids)
    }

    /// Get a session by ID
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (session_id)))]
    pub fn get(&self, session_id: i64) -> Result<Option<Session>> {
        let id_val = crate::ruby_bridge::get_ruby()?
            .eval::<Value>(&format!("{}", session_id))
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
            })?;

        let session_val = call_method(self.ruby_sessions, "[]", &[id_val])?;

        // Check if nil
        if is_nil(session_val) {
            Ok(None)
        } else {
            Ok(Some(Session {
                ruby_session: session_val,
                session_id,
            }))
        }
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<SessionManager count={}>", self.list()?.len()))
    }
}

#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct Session {
    pub(crate) ruby_session: Value,
    pub session_id: i64,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl Session {
    /// Get session type
    pub fn session_type(&self) -> Result<String> {
        let type_val = call_method(self.ruby_session, "type", &[])?;
        Ok(value_to_string(type_val)?)
    }

    /// Get session info
    pub fn info(&self) -> Result<String> {
        let info_val = call_method(self.ruby_session, "info", &[])?;
        Ok(value_to_string(info_val)?)
    }

    /// Check if session is alive
    pub fn alive(&self) -> Result<bool> {
        let alive_val = call_method(self.ruby_session, "alive?", &[])?;
        Ok(crate::ruby_bridge::value_to_bool(alive_val)?)
    }

    /// Kill the session
    pub fn kill(&self) -> Result<()> {
        call_method(self.ruby_session, "kill", &[])?;
        Ok(())
    }

    /// Write data to the session
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (data)))]
    pub fn write(&self, data: &str) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let data_val = ruby.str_new(data).as_value();

        let result = call_method(self.ruby_session, "write", &[data_val])?;

        // Try to convert to integer (bytes written)
        let bytes_written: i64 = TryConvert::try_convert(result).unwrap_or(data.len() as i64);

        Ok(bytes_written as usize)
    }

    /// Read data from the session
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (length=None)))]
    pub fn read(&self, length: Option<usize>) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        let result = if let Some(len) = length {
            let len_val = ruby
                .eval::<Value>(&format!("{}", len))
                .map_err(|e| AssassinateError::ConversionError(e.to_string()))?;
            call_method(self.ruby_session, "read", &[len_val])?
        } else {
            call_method(self.ruby_session, "read", &[])?
        };

        if is_nil(result) {
            Ok(String::new())
        } else {
            Ok(value_to_string(result)?)
        }
    }

    /// Execute a command in the session (shell command)
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (command)))]
    pub fn execute(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Write command
        self.write(&format!("{}\n", command))?;

        // Give it time to execute (you may want to make this configurable)
        ruby.eval::<Value>("sleep 0.5")
            .map_err(|e| AssassinateError::RubyError(e.to_string()))?;

        // Read response
        self.read(None)
    }

    /// Run a Meterpreter command (if it's a meterpreter session)
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (command)))]
    pub fn run_cmd(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let cmd_val = ruby.str_new(command).as_value();

        let result = call_method(self.ruby_session, "run_cmd", &[cmd_val])?;

        if is_nil(result) {
            Ok(String::new())
        } else {
            Ok(value_to_string(result)?)
        }
    }

    /// Get session description
    pub fn desc(&self) -> Result<String> {
        let desc_val = call_method(self.ruby_session, "desc", &[])?;
        Ok(value_to_string(desc_val)?)
    }

    /// Get tunnel peer (remote address)
    pub fn tunnel_peer(&self) -> Result<String> {
        let peer_val = call_method(self.ruby_session, "tunnel_peer", &[])?;
        Ok(value_to_string(peer_val)?)
    }

    /// Get target host
    pub fn target_host(&self) -> Result<String> {
        let host_val = call_method(self.ruby_session, "target_host", &[])?;
        Ok(value_to_string(host_val)?)
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Session id={} type='{}' alive={}>",
            self.session_id,
            self.session_type()?,
            self.alive()?
        ))
    }
}

#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct PayloadGenerator {
    ruby_framework: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl PayloadGenerator {
    #[cfg_attr(feature = "python-bindings", new)]
    pub fn new(framework: &Framework) -> Result<Self> {
        Ok(PayloadGenerator {
            ruby_framework: framework.ruby_framework,
        })
    }

    /// Generate a payload
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (payload_name, **options)))]
    pub fn generate(
        &self,
        payload_name: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if is_nil(payload) {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            ))
            .into());
        }

        // Set options
        if let Some(opts_map) = options {
            let datastore = call_method(payload, "datastore", &[])?;
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the payload
        let generated = call_method(payload, "generate", &[])?;

        if is_nil(generated) {
            return Err(
                AssassinateError::PayloadError("Failed to generate payload".to_string()).into(),
            );
        }

        // Convert Ruby string to bytes
        let bytes_str = value_to_string(generated)?;
        Ok(bytes_str.into_bytes())
    }

    /// Generate a payload and encode it
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (payload_name, encoder=None, iterations=1, **options)))]
    pub fn generate_encoded(
        &self,
        payload_name: &str,
        encoder: Option<&str>,
        iterations: Option<i32>,
        options: Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if is_nil(payload) {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            ))
            .into());
        }

        // Get datastore
        let datastore = call_method(payload, "datastore", &[])?;

        // Set encoder if provided
        if let Some(enc) = encoder {
            let encoder_key = ruby.str_new("ENCODER").as_value();
            let encoder_val = ruby.str_new(enc).as_value();
            call_method(datastore, "[]=", &[encoder_key, encoder_val])?;
        }

        // Set iterations if provided
        if let Some(iter) = iterations {
            let iter_key = ruby.str_new("Iterations").as_value();
            let iter_val = ruby
                .eval::<Value>(&format!("{}", iter))
                .map_err(|e| AssassinateError::ConversionError(e.to_string()))?;
            call_method(datastore, "[]=", &[iter_key, iter_val])?;
        }

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the payload
        let generated = call_method(payload, "generate", &[])?;

        if is_nil(generated) {
            return Err(
                AssassinateError::PayloadError("Failed to generate payload".to_string()).into(),
            );
        }

        // Convert Ruby string to bytes
        let bytes_str = value_to_string(generated)?;
        Ok(bytes_str.into_bytes())
    }

    /// List all available payloads
    pub fn list_payloads(&self) -> Result<Vec<String>> {
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payloads = call_method(modules_mgr, "payloads", &[])?;
        let refnames = call_method(payloads, "module_refnames", &[])?;

        let payload_list: Vec<String> =
            TryConvert::try_convert(refnames).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert payload list: {}", e))
            })?;

        Ok(payload_list)
    }

    /// Generate a standalone executable payload
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (payload_name, platform, arch, **options)))]
    pub fn generate_executable(
        &self,
        payload_name: &str,
        platform: &str,
        arch: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if is_nil(payload) {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            ))
            .into());
        }

        // Get datastore
        let datastore = call_method(payload, "datastore", &[])?;

        // Set platform and arch
        let platform_key = ruby.str_new("Platform").as_value();
        let platform_val = ruby.str_new(platform).as_value();
        call_method(datastore, "[]=", &[platform_key, platform_val])?;

        let arch_key = ruby.str_new("Arch").as_value();
        let arch_val = ruby.str_new(arch).as_value();
        call_method(datastore, "[]=", &[arch_key, arch_val])?;

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the raw payload
        let raw_payload = call_method(payload, "generate", &[])?;

        if is_nil(raw_payload) {
            return Err(
                AssassinateError::PayloadError("Failed to generate payload".to_string()).into(),
            );
        }

        // Store raw_payload in global variable temporarily
        ruby.eval::<Value>(&format!("$temp_raw_payload = {:?}", raw_payload))
            .map_err(|e| AssassinateError::RubyError(e.to_string()))?;
        ruby.eval::<Value>(&format!("$temp_framework = {:?}", self.ruby_framework))
            .map_err(|e| AssassinateError::RubyError(e.to_string()))?;

        // Use temporary variables in eval
        let exe_code = format!(
            r#"
            Msf::Util::EXE.to_executable($temp_framework, '{}', '{}', $temp_raw_payload)
            "#,
            arch, platform
        );

        let exe = ruby
            .eval::<Value>(&exe_code)
            .map_err(|e| AssassinateError::PayloadError(e.to_string()))?;

        if is_nil(exe) {
            return Err(AssassinateError::PayloadError(
                "Failed to generate executable".to_string(),
            )
            .into());
        }

        // Convert Ruby string to bytes
        let bytes_str = value_to_string(exe)?;
        Ok(bytes_str.into_bytes())
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok("<PayloadGenerator>".to_string())
    }
}
