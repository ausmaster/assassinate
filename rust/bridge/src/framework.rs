//! Framework types and operations for Metasploit Framework interaction

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, create_framework, is_nil, value_to_string};
use magnus::{value::ReprValue, TryConvert, Value};
use std::collections::HashMap;

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
    /// Create a new Framework instance
    pub fn new(options: Option<HashMap<String, String>>) -> Result<Self> {
        let opts_json = options.and_then(|o| serde_json::to_value(o).ok());

        let ruby_framework = create_framework(opts_json)?;

        Ok(Framework { ruby_framework })
    }

    /// Get the Metasploit Framework version
    pub fn version(&self) -> Result<String> {
        let version_val = call_method(self.ruby_framework, "version", &[])?;
        value_to_string(version_val)
    }

    /// List all module reference names for a given type
    pub fn list_modules(&self, module_type: &str) -> Result<Vec<String>> {
        let modules_manager = call_method(self.ruby_framework, "modules", &[])?;

        // MSF uses plural names for module types (exploits, not exploit)
        let plural_type = match module_type {
            "exploit" => "exploits",
            "auxiliary" => "auxiliary",
            "payload" => "payloads",
            "encoder" => "encoders",
            "nop" => "nops",
            "post" => "post",
            _ => module_type,
        };

        let module_set = call_method(modules_manager, plural_type, &[])?;

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

    /// Get database manager
    pub fn db(&self) -> Result<DbManager> {
        let db_val = call_method(self.ruby_framework, "db", &[])?;

        Ok(DbManager { ruby_db: db_val })
    }

    /// Search for modules
    pub fn search(&self, query: &str) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let query_val = ruby.str_new(query).as_value();

        let results_val = call_method(self.ruby_framework, "search", &[query_val])?;

        // Search returns an array of metadata objects - extract fullname from each
        let results_array: magnus::RArray = TryConvert::try_convert(results_val)
            .map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert search results to array: {}", e))
            })?;

        let mut results = Vec::new();
        for item in results_array.each() {
            let metadata_obj = item.map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to iterate search results: {}", e))
            })?;

            // Extract fullname from metadata object
            let fullname_val = call_method(metadata_obj, "fullname", &[])?;
            let fullname = value_to_string(fullname_val)?;
            results.push(fullname);
        }

        Ok(results)
    }

    /// Get jobs manager
    pub fn jobs(&self) -> Result<JobManager> {
        let jobs_val = call_method(self.ruby_framework, "jobs", &[])?;

        Ok(JobManager { ruby_jobs: jobs_val })
    }

    /// Get framework threads configuration
    pub fn threads(&self) -> Result<i64> {
        let threads_val = call_method(self.ruby_framework, "threads", &[])?;

        // MSF returns ThreadManager object - check if it responds to max_threads or similar
        // Try to get the thread count - if threads is nil, return 0
        if threads_val.is_nil() {
            return Ok(0);
        }

        // Try to call max_threads method
        match call_method(threads_val, "max_threads", &[]) {
            Ok(max_threads_val) => {
                let threads: i64 = TryConvert::try_convert(max_threads_val).map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!("Failed to convert max_threads: {}", e))
                })?;
                Ok(threads)
            }
            Err(_) => {
                // If max_threads doesn't work, try other methods or return a default
                Ok(1) // Default to 1 thread
            }
        }
    }

    /// Check if framework has threads configured
    pub fn threads_enabled(&self) -> Result<bool> {
        let threads_val = call_method(self.ruby_framework, "threads?", &[])?;
        crate::ruby_bridge::value_to_bool(threads_val)
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
        value_to_string(name_val)
    }

    /// Get module full name
    pub fn fullname(&self) -> Result<String> {
        let fullname_val = call_method(self.ruby_module, "fullname", &[])?;
        value_to_string(fullname_val)
    }

    /// Get module description
    pub fn description(&self) -> Result<String> {
        let desc_val = call_method(self.ruby_module, "description", &[])?;
        value_to_string(desc_val)
    }

    /// Get module type
    pub fn module_type(&self) -> Result<String> {
        let type_val = call_method(self.ruby_module, "type", &[])?;
        value_to_string(type_val)
    }

    /// Get module datastore
    pub fn datastore(&self) -> Result<DataStore> {
        let datastore_val = call_method(self.ruby_module, "datastore", &[])?;

        Ok(DataStore {
            ruby_datastore: datastore_val,
        })
    }

    /// Set a datastore option
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (key, value))]
    pub fn set_option(&self, key: &str, value: &str) -> Result<()> {
        let datastore = self.datastore()?;
        datastore.set(key, value)?;
        Ok(())
    }

    /// Get a datastore option
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (key))]
    pub fn get_option(&self, key: &str) -> Result<Option<String>> {
        let datastore = self.datastore()?;
        datastore.get(key)
    }

    /// Validate module configuration
    pub fn validate(&self) -> Result<bool> {
        let result = call_method(self.ruby_module, "validate", &[]);

        match result {
            Ok(_) => Ok(true),
            Err(e) => Err(AssassinateError::ModuleValidationError(e.to_string())),
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
        crate::ruby_bridge::value_to_bool(result)
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

    /// Get module authors
    pub fn author(&self) -> Result<Vec<String>> {
        let author_val = call_method(self.ruby_module, "author", &[])?;

        // author is an array of Author objects, convert to strings
        let authors: Vec<String> = TryConvert::try_convert(author_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert authors: {}", e))
        })?;

        Ok(authors)
    }

    /// Get module references (CVE, BID, URL, etc.)
    pub fn references(&self) -> Result<Vec<String>> {
        let refs_val = call_method(self.ruby_module, "references", &[])?;

        // References is an array, convert each to string
        let refs: Vec<String> = TryConvert::try_convert(refs_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert references: {}", e))
        })?;

        Ok(refs)
    }

    /// Get module options (returns the options attribute reader)
    pub fn options(&self) -> Result<String> {
        let options_val = call_method(self.ruby_module, "options", &[])?;
        value_to_string(options_val)
    }

    /// Get module target platforms
    pub fn platform(&self) -> Result<Vec<String>> {
        let platform_val = call_method(self.ruby_module, "platform", &[])?;

        // Platform can be PlatformList or nil
        if is_nil(platform_val) {
            return Ok(vec![]);
        }

        // Try to convert to array of strings
        let platforms: Vec<String> =
            TryConvert::try_convert(platform_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert platforms: {}", e))
            })?;

        Ok(platforms)
    }

    /// Get module target architectures
    pub fn arch(&self) -> Result<Vec<String>> {
        let arch_val = call_method(self.ruby_module, "arch", &[])?;

        // Arch can be an array or nil
        if is_nil(arch_val) {
            return Ok(vec![]);
        }

        // Try to convert to array of strings
        let archs: Vec<String> = TryConvert::try_convert(arch_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert architectures: {}", e))
        })?;

        Ok(archs)
    }

    /// Get exploit targets (for exploit modules only)
    pub fn targets(&self) -> Result<Vec<String>> {
        // Check if module responds to targets
        let ruby = crate::ruby_bridge::get_ruby()?;
        let method_name = ruby.str_new("targets").as_value();

        match call_method(self.ruby_module, "respond_to?", &[method_name]) {
            Ok(responds) if crate::ruby_bridge::value_to_bool(responds)? => {
                let targets_val = call_method(self.ruby_module, "targets", &[])?;

                if is_nil(targets_val) {
                    return Ok(vec![]);
                }

                // Targets is an array of Target objects - extract name from each
                let targets_array: magnus::RArray = TryConvert::try_convert(targets_val)
                    .map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!("Failed to convert targets to array: {}", e))
                    })?;

                let mut target_names = Vec::new();
                for target_obj in targets_array.into_iter() {
                    // Extract name from target object
                    let name_val = call_method(target_obj, "name", &[])?;
                    let name = value_to_string(name_val)?;
                    target_names.push(name);
                }

                Ok(target_names)
            }
            _ => Ok(vec![]),
        }
    }

    /// Get vulnerability disclosure date
    pub fn disclosure_date(&self) -> Result<Option<String>> {
        let date_val = call_method(self.ruby_module, "disclosure_date", &[])?;

        if is_nil(date_val) {
            Ok(None)
        } else {
            Ok(Some(value_to_string(date_val)?))
        }
    }

    /// Get module rank (e.g., "excellent", "great", "good", "normal", "average", "low", "manual")
    pub fn rank(&self) -> Result<String> {
        let rank_val = call_method(self.ruby_module, "rank", &[])?;
        value_to_string(rank_val)
    }

    /// Check if module requires privileged access
    pub fn privileged(&self) -> Result<bool> {
        let priv_val = call_method(self.ruby_module, "privileged", &[])?;
        crate::ruby_bridge::value_to_bool(priv_val)
    }

    /// Get module license
    pub fn license(&self) -> Result<String> {
        let license_val = call_method(self.ruby_module, "license", &[])?;
        value_to_string(license_val)
    }

    /// Get module aliases
    pub fn aliases(&self) -> Result<Vec<String>> {
        let aliases_val = call_method(self.ruby_module, "aliases", &[])?;

        // Convert to array of strings
        let aliases: Vec<String> = TryConvert::try_convert(aliases_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert aliases: {}", e))
        })?;

        Ok(aliases)
    }

    /// Get module notes
    pub fn notes(&self) -> Result<HashMap<String, String>> {
        let notes_val = call_method(self.ruby_module, "notes", &[])?;

        if is_nil(notes_val) {
            return Ok(HashMap::new());
        }

        // Try to convert to JSON and parse (simpler approach for complex structures)
        let ruby = crate::ruby_bridge::get_ruby()?;
        let json_module: magnus::Value = ruby.eval("JSON")?;
        let json_str_val = call_method(json_module, "generate", &[notes_val])?;
        let json_str = value_to_string(json_str_val)?;

        // Parse JSON into HashMap<String, serde_json::Value> then convert to HashMap<String, String>
        let notes_json: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| AssassinateError::ConversionError(format!("Failed to parse notes JSON: {}", e)))?;

        let mut notes = HashMap::new();
        if let Some(obj) = notes_json.as_object() {
            for (key, value) in obj {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Array(arr) => {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                    _ => value.to_string(),
                };
                notes.insert(key.clone(), value_str);
            }
        }

        Ok(notes)
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

        // Convert to HashMap<String, Value> first to handle nulls
        let raw_dict: HashMap<String, serde_json::Value> = serde_json::from_value(json).map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to convert datastore to dict: {}", e))
        })?;

        // Convert values to strings, treating null as empty string
        let dict: HashMap<String, String> = raw_dict
            .into_iter()
            .map(|(k, v)| {
                let str_val = match v {
                    serde_json::Value::Null => String::new(),
                    serde_json::Value::String(s) => s,
                    _ => v.to_string(),
                };
                (k, str_val)
            })
            .collect();

        Ok(dict)
    }

    /// Delete a key from datastore
    #[cfg_attr(feature = "python-bindings", pyo3(signature = (key)))]
    pub fn delete(&self, key: &str) -> Result<()> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let key_val = ruby.str_new(key).as_value();

        call_method(self.ruby_datastore, "delete", &[key_val])?;
        Ok(())
    }

    /// Get all keys
    pub fn keys(&self) -> Result<Vec<String>> {
        let keys_val = call_method(self.ruby_datastore, "keys", &[])?;

        let keys: Vec<String> = TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert keys: {}", e))
        })?;

        Ok(keys)
    }

    /// Clear all values
    pub fn clear(&self) -> Result<()> {
        call_method(self.ruby_datastore, "clear", &[])?;
        Ok(())
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
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (session_id))]
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

    /// Kill a session by ID
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (session_id))]
    pub fn kill(&self, session_id: i64) -> Result<bool> {
        let id_val = crate::ruby_bridge::get_ruby()?
            .eval::<Value>(&format!("{}", session_id))
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
            })?;

        // Call delete method on sessions hash
        let result_val = call_method(self.ruby_sessions, "delete", &[id_val])?;

        // If delete returns nil, session didn't exist
        Ok(!is_nil(result_val))
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
        value_to_string(type_val)
    }

    /// Get session info
    pub fn info(&self) -> Result<String> {
        let info_val = call_method(self.ruby_session, "info", &[])?;
        value_to_string(info_val)
    }

    /// Check if session is alive
    pub fn alive(&self) -> Result<bool> {
        let alive_val = call_method(self.ruby_session, "alive?", &[])?;
        crate::ruby_bridge::value_to_bool(alive_val)
    }

    /// Kill the session
    pub fn kill(&self) -> Result<()> {
        call_method(self.ruby_session, "kill", &[])?;
        Ok(())
    }

    /// Write data to the session
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (data))]
    pub fn write(&self, data: &str) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let data_val = ruby.str_new(data).as_value();

        let result = call_method(self.ruby_session, "write", &[data_val])?;

        // Try to convert to integer (bytes written)
        let bytes_written: i64 = TryConvert::try_convert(result).unwrap_or(data.len() as i64);

        Ok(bytes_written as usize)
    }

    /// Read data from the session
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (length=None))]
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
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (command))]
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
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (command))]
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
        value_to_string(desc_val)
    }

    /// Get tunnel peer (remote address)
    pub fn tunnel_peer(&self) -> Result<String> {
        let peer_val = call_method(self.ruby_session, "tunnel_peer", &[])?;
        value_to_string(peer_val)
    }

    /// Get target host
    pub fn target_host(&self) -> Result<String> {
        let host_val = call_method(self.ruby_session, "target_host", &[])?;
        value_to_string(host_val)
    }

    /// Get session host
    pub fn session_host(&self) -> Result<String> {
        let host_val = call_method(self.ruby_session, "session_host", &[])?;
        value_to_string(host_val)
    }

    /// Get session port
    pub fn session_port(&self) -> Result<i64> {
        let port_val = call_method(self.ruby_session, "session_port", &[])?;
        TryConvert::try_convert(port_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert port: {}", e))
        })
    }

    /// Get exploit that created this session
    pub fn via_exploit(&self) -> Result<String> {
        let exploit_val = call_method(self.ruby_session, "via_exploit", &[])?;
        value_to_string(exploit_val)
    }

    /// Get payload that created this session
    pub fn via_payload(&self) -> Result<String> {
        let payload_val = call_method(self.ruby_session, "via_payload", &[])?;
        value_to_string(payload_val)
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

/// Database manager
#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct DbManager {
    pub(crate) ruby_db: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl DbManager {
    /// Get all hosts
    pub fn hosts(&self) -> Result<Vec<String>> {
        let hosts_val = call_method(self.ruby_db, "hosts", &[])?;

        // Convert to array of strings (host IPs)
        let hosts: Vec<String> = TryConvert::try_convert(hosts_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert hosts: {}", e))
        })?;

        Ok(hosts)
    }

    /// Get all services
    pub fn services(&self) -> Result<Vec<String>> {
        let services_val = call_method(self.ruby_db, "services", &[])?;

        // Convert to array of strings
        let services: Vec<String> =
            TryConvert::try_convert(services_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert services: {}", e))
            })?;

        Ok(services)
    }

    /// Report a host
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (**opts))]
    pub fn report_host(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        let host_val = call_method(self.ruby_db, "report_host", &[opts_val])?;

        // Get host ID
        let id: i64 = TryConvert::try_convert(host_val).unwrap_or(0);
        Ok(id)
    }

    /// Report a service
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (**opts))]
    pub fn report_service(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        let service_val = call_method(self.ruby_db, "report_service", &[opts_val])?;

        // Get service ID
        let id: i64 = TryConvert::try_convert(service_val).unwrap_or(0);
        Ok(id)
    }

    /// Report a vulnerability
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (**opts))]
    pub fn report_vuln(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        let vuln_val = call_method(self.ruby_db, "report_vuln", &[opts_val])?;

        // Get vuln ID
        let id: i64 = TryConvert::try_convert(vuln_val).unwrap_or(0);
        Ok(id)
    }

    /// Report a credential
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (**opts))]
    pub fn report_cred(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        let cred_val = call_method(self.ruby_db, "report_cred", &[opts_val])?;

        // Get cred ID
        let id: i64 = TryConvert::try_convert(cred_val).unwrap_or(0);
        Ok(id)
    }

    /// Get all vulnerabilities
    pub fn vulns(&self) -> Result<Vec<String>> {
        let vulns_val = call_method(self.ruby_db, "vulns", &[])?;

        // Convert to array of strings
        let vulns: Vec<String> = TryConvert::try_convert(vulns_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert vulns: {}", e))
        })?;

        Ok(vulns)
    }

    /// Get all credentials
    pub fn creds(&self) -> Result<Vec<String>> {
        let creds_val = call_method(self.ruby_db, "creds", &[])?;

        // Convert to array of strings
        let creds: Vec<String> = TryConvert::try_convert(creds_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert creds: {}", e))
        })?;

        Ok(creds)
    }

    /// Get all loot
    pub fn loot(&self) -> Result<Vec<String>> {
        let loot_val = call_method(self.ruby_db, "loot", &[])?;

        // Convert to array of strings
        let loot: Vec<String> = TryConvert::try_convert(loot_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert loot: {}", e))
        })?;

        Ok(loot)
    }

    /// Helper function to report to database (reduces code duplication)
    fn report_to_db(&self, method_name: &str, opts: Option<HashMap<String, String>>) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        let result_val = call_method(self.ruby_db, method_name, &[opts_val])?;
        let id: i64 = TryConvert::try_convert(result_val).unwrap_or(0);
        Ok(id)
    }

    /// Report a host (raw version without PyO3)
    pub fn report_host_raw(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_host", opts)
    }

    /// Report a service (raw version without PyO3)
    pub fn report_service_raw(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_service", opts)
    }

    /// Report a vulnerability (raw version without PyO3)
    pub fn report_vuln_raw(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_vuln", opts)
    }

    /// Report a credential (raw version without PyO3)
    pub fn report_cred_raw(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_cred", opts)
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok("<DbManager>".to_string())
    }
}

/// Job manager
#[cfg_attr(feature = "python-bindings", pyclass(unsendable))]
#[derive(Clone)]
pub struct JobManager {
    pub(crate) ruby_jobs: Value,
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl JobManager {
    /// List all job IDs
    pub fn list(&self) -> Result<Vec<String>> {
        let keys_val = call_method(self.ruby_jobs, "keys", &[])?;

        let job_ids: Vec<String> = TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert job IDs: {}", e))
        })?;

        Ok(job_ids)
    }

    /// Get job by ID
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (job_id))]
    pub fn get(&self, job_id: &str) -> Result<Option<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        let job_val = call_method(self.ruby_jobs, "[]", &[id_val])?;

        if is_nil(job_val) {
            Ok(None)
        } else {
            Ok(Some(value_to_string(job_val)?))
        }
    }

    /// Kill a job by ID
    #[cfg(feature = "python-bindings")]
    #[pyo3(signature = (job_id))]
    pub fn kill(&self, job_id: &str) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        match call_method(self.ruby_jobs, "stop", &[id_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<JobManager jobs={}>", self.list()?.len()))
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
            )));
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
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Convert Ruby binary string to bytes (don't use value_to_string - binary data isn't UTF-8)
        let rstring: magnus::RString = TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert payload to RString: {}", e))
        })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
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
            )));
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
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Convert Ruby binary string to bytes (don't use value_to_string - binary data isn't UTF-8)
        let rstring: magnus::RString = TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert payload to RString: {}", e))
        })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
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
            )));
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
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Call Msf::Util::EXE.to_executable
        // We need to properly construct arch array and platform list
        let ruby = magnus::Ruby::get().unwrap();

        // Create options hash
        let opts = ruby.hash_new();

        // Get the payload's arch and platform directly from the payload module
        // This ensures we use the correct arch/platform values that MSF expects
        let payload_arch = call_method(payload, "arch", &[])?;
        let payload_platform = call_method(payload, "platform", &[])?;

        // Get Msf::Util::EXE module
        let exe_module: Value = ruby.eval("Msf::Util::EXE")
            .map_err(|e| AssassinateError::RubyError(format!("Failed to get Msf::Util::EXE: {}", e)))?;

        // Call to_executable with the payload's own arch/platform
        // These are already in the correct format (arrays of constants)
        let exe: Value = exe_module.funcall("to_executable",
            (self.ruby_framework, payload_arch, payload_platform, raw_payload, opts))
            .map_err(|e| AssassinateError::RubyError(format!("to_executable failed: {}", e)))?;

        if is_nil(exe) {
            return Err(AssassinateError::PayloadError(
                format!("to_executable returned nil for arch={}, platform={}", arch, platform)
            ));
        }

        // Convert Ruby binary string to bytes
        let rstring: magnus::RString = TryConvert::try_convert(exe).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert executable to RString: {}. Value type: {:?}", e, exe))
        })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> Result<String> {
        Ok("<PayloadGenerator>".to_string())
    }
}
