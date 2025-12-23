//! Framework types and operations for Metasploit Framework interaction

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{
    call_method, create_framework, is_nil, ruby_array_to_strings, to_ruby_str, value_to_bool,
    value_to_string,
};
use magnus::{value::ReprValue, StaticSymbol, TryConvert, Value};
use std::collections::HashMap;

/// Core Metasploit Framework interface
///
/// This type provides access to the Metasploit Framework functionality through Ruby FFI.
#[derive(Clone)]
pub struct Framework {
    pub(crate) ruby_framework: Value,
}

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
        let results_array: magnus::RArray =
            TryConvert::try_convert(results_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert search results to array: {}",
                    e
                ))
            })?;

        let mut results = Vec::new();
        for metadata_obj in results_array.into_iter() {
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

        Ok(JobManager {
            ruby_jobs: jobs_val,
        })
    }

    /// Get plugin manager
    pub fn plugins(&self) -> Result<PluginManager> {
        let plugins_val = call_method(self.ruby_framework, "plugins", &[])?;

        Ok(PluginManager {
            ruby_plugins: plugins_val,
        })
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
                let threads: i64 =
                    TryConvert::try_convert(max_threads_val).map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!(
                            "Failed to convert max_threads: {}",
                            e
                        ))
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

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<Framework version={}>", self.version()?))
    }
}

/// Metasploit module instance
#[derive(Clone)]
pub struct Module {
    pub(crate) ruby_module: Value,
}

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
    pub fn set_option(&self, key: &str, value: &str) -> Result<()> {
        let datastore = self.datastore()?;
        datastore.set(key, value)?;
        Ok(())
    }

    /// Get a datastore option
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
                // Get compatible payloads - returns array of [name, class] tuples
                let payloads_val = call_method(self.ruby_module, "compatible_payloads", &[])?;

                // Get array length
                let array_len: usize = TryConvert::try_convert(
                    call_method(payloads_val, "length", &[])?
                ).map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!("Failed to get array length: {}", e))
                })?;

                // Iterate through array and extract first element (payload name) from each tuple
                let mut result = Vec::with_capacity(array_len);
                for i in 0..array_len {
                    let idx_val = ruby.integer_from_i64(i as i64).as_value();
                    // Get the [name, class] tuple
                    let tuple_val = call_method(payloads_val, "[]", &[idx_val])?;
                    // Get the first element (name) from the tuple
                    let zero_val = ruby.integer_from_i64(0).as_value();
                    let name_val = call_method(tuple_val, "[]", &[zero_val])?;
                    let name = value_to_string(name_val)?;
                    result.push(name);
                }

                Ok(result)
            }
            _ => Ok(vec![]),
        }
    }

    /// Get available actions for this auxiliary/post module
    /// Returns list of action names
    pub fn actions(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let method_name = ruby.str_new("actions").as_value();

        // Check if module responds to actions
        match call_method(self.ruby_module, "respond_to?", &[method_name]) {
            Ok(responds) if crate::ruby_bridge::value_to_bool(responds)? => {
                // Get actions array
                let actions_val = call_method(self.ruby_module, "actions", &[])?;

                // Get array length
                let array_len: usize = TryConvert::try_convert(
                    call_method(actions_val, "length", &[])?
                ).map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!("Failed to get actions array length: {}", e))
                })?;

                // Iterate through actions and extract names
                let mut result = Vec::with_capacity(array_len);
                for i in 0..array_len {
                    let idx_val = ruby.integer_from_i64(i as i64).as_value();
                    let action_val = call_method(actions_val, "[]", &[idx_val])?;
                    let name_val = call_method(action_val, "name", &[])?;
                    let name = value_to_string(name_val)?;
                    result.push(name);
                }

                Ok(result)
            }
            _ => Ok(vec![]),
        }
    }

    /// Get the default action for this auxiliary/post module
    /// Returns None if module doesn't support actions or has no default
    pub fn default_action(&self) -> Result<Option<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let method_name = ruby.str_new("default_action").as_value();

        // Check if module responds to default_action
        match call_method(self.ruby_module, "respond_to?", &[method_name]) {
            Ok(responds) if crate::ruby_bridge::value_to_bool(responds)? => {
                let default_val = call_method(self.ruby_module, "default_action", &[])?;

                if is_nil(default_val) {
                    Ok(None)
                } else {
                    let name = value_to_string(default_val)?;
                    Ok(Some(name))
                }
            }
            _ => Ok(None),
        }
    }

    /// Get the current action for this auxiliary/post module
    /// This looks up datastore['ACTION'] and returns the matching action name
    /// Falls back to default_action if ACTION is not set
    /// Returns None if module doesn't support actions
    pub fn action(&self) -> Result<Option<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let method_name = ruby.str_new("action").as_value();

        // Check if module responds to action
        match call_method(self.ruby_module, "respond_to?", &[method_name]) {
            Ok(responds) if crate::ruby_bridge::value_to_bool(responds)? => {
                let action_val = call_method(self.ruby_module, "action", &[])?;

                if is_nil(action_val) {
                    Ok(None)
                } else {
                    // action returns an AuxiliaryAction object, get its name
                    let name_val = call_method(action_val, "name", &[])?;
                    let name = value_to_string(name_val)?;
                    Ok(Some(name))
                }
            }
            _ => Ok(None),
        }
    }

    /// Get module authors
    pub fn author(&self) -> Result<Vec<String>> {
        let author_val = call_method(self.ruby_module, "author", &[])?;

        // author is an array of Author objects, convert to strings
        let authors: Vec<String> =
            TryConvert::try_convert(author_val).map_err(|e: magnus::Error| {
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
        let archs: Vec<String> =
            TryConvert::try_convert(arch_val).map_err(|e: magnus::Error| {
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
                let targets_array: magnus::RArray =
                    TryConvert::try_convert(targets_val).map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!(
                            "Failed to convert targets to array: {}",
                            e
                        ))
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
        let aliases: Vec<String> =
            TryConvert::try_convert(aliases_val).map_err(|e: magnus::Error| {
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
        let notes_json: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to parse notes JSON: {}", e))
        })?;

        let mut notes = HashMap::new();
        if let Some(obj) = notes_json.as_object() {
            for (key, value) in obj {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Array(arr) => arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                        .join(", "),
                    _ => value.to_string(),
                };
                notes.insert(key.clone(), value_str);
            }
        }

        Ok(notes)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Module name='{}' type='{}'>",
            self.fullname()?,
            self.module_type()?
        ))
    }
}

#[derive(Clone)]
pub struct DataStore {
    pub(crate) ruby_datastore: Value,
}

impl DataStore {
    /// Set a value in the datastore
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        let key_val = crate::ruby_bridge::get_ruby()?.str_new(key).as_value();
        let value_val = crate::ruby_bridge::get_ruby()?.str_new(value).as_value();

        call_method(self.ruby_datastore, "[]=", &[key_val, value_val])?;

        Ok(())
    }

    /// Get a value from the datastore
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
        let raw_dict: HashMap<String, serde_json::Value> =
            serde_json::from_value(json).map_err(|e| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert datastore to dict: {}",
                    e
                ))
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

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<DataStore {}>", self.to_dict()?.len()))
    }
}

#[derive(Clone)]
pub struct SessionManager {
    pub(crate) ruby_sessions: Value,
}

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

    /// Get a session by ID (raw version without PyO3)
    pub fn get_raw(&self, session_id: i64) -> Result<Option<Value>> {
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
            Ok(Some(session_val))
        }
    }

    /// Kill a session by ID (raw version without PyO3)
    pub fn kill_raw(&self, session_id: i64) -> Result<bool> {
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

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<SessionManager count={}>", self.list()?.len()))
    }
}

#[derive(Clone)]
pub struct Session {
    pub(crate) ruby_session: Value,
    pub session_id: i64,
}

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
    pub fn write(&self, data: &str) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let data_val = ruby.str_new(data).as_value();

        let result = call_method(self.ruby_session, "write", &[data_val])?;

        // Try to convert to integer (bytes written)
        let bytes_written: i64 = TryConvert::try_convert(result).unwrap_or(data.len() as i64);

        Ok(bytes_written as usize)
    }

    /// Read data from the session
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

    /// Create Session from raw Ruby value (for daemon use)
    pub fn from_raw(session_val: Value, session_id: i64) -> Self {
        Session {
            ruby_session: session_val,
            session_id,
        }
    }

    /// Write data to the session (raw version without PyO3)
    pub fn write_raw(&self, data: &str) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let data_val = ruby.str_new(data).as_value();

        let result = call_method(self.ruby_session, "write", &[data_val])?;

        // Try to convert to integer (bytes written)
        let bytes_written: i64 = TryConvert::try_convert(result).unwrap_or(data.len() as i64);

        Ok(bytes_written as usize)
    }

    /// Read data from the session (raw version without PyO3)
    pub fn read_raw(&self, length: Option<usize>) -> Result<String> {
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

    /// Execute a command in the session (raw version without PyO3)
    pub fn execute_raw(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Write command
        self.write_raw(&format!("{}\n", command))?;

        // Give it time to execute
        ruby.eval::<Value>("sleep 0.5")
            .map_err(|e| AssassinateError::RubyError(e.to_string()))?;

        // Read response
        self.read_raw(None)
    }

    /// Run a Meterpreter command (raw version without PyO3)
    pub fn run_cmd_raw(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let cmd_val = ruby.str_new(command).as_value();

        let result = call_method(self.ruby_session, "run_cmd", &[cmd_val])?;

        if is_nil(result) {
            Ok(String::new())
        } else {
            Ok(value_to_string(result)?)
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Session id={} type='{}' alive={}>",
            self.session_id,
            self.session_type()?,
            self.alive()?
        ))
    }

    // ========== Meterpreter Extension Helpers (DRY) ==========

    /// Get the fs extension object (caches fs access pattern)
    fn fs(&self) -> Result<Value> {
        call_method(self.ruby_session, "fs", &[])
    }

    /// Get fs.dir for directory operations
    fn fs_dir_ext(&self) -> Result<Value> {
        call_method(self.fs()?, "dir", &[])
    }

    /// Get fs.file for file operations
    fn fs_file_ext(&self) -> Result<Value> {
        call_method(self.fs()?, "file", &[])
    }

    /// Get the sys extension object for system operations
    fn sys(&self) -> Result<Value> {
        call_method(self.ruby_session, "sys", &[])
    }

    /// Get sys.process for process operations
    fn sys_process(&self) -> Result<Value> {
        call_method(self.sys()?, "process", &[])
    }

    /// Get sys.config for system configuration
    fn sys_config(&self) -> Result<Value> {
        call_method(self.sys()?, "config", &[])
    }

    /// Get the net extension object for network operations
    fn net(&self) -> Result<Value> {
        call_method(self.ruby_session, "net", &[])
    }

    /// Get net.config for network configuration
    fn net_config(&self) -> Result<Value> {
        call_method(self.net()?, "config", &[])
    }

    /// Check if this session has a specific extension/method
    fn has_extension(&self, name: &str) -> Result<bool> {
        let method_name = to_ruby_str(name)?;
        let result = call_method(self.ruby_session, "respond_to?", &[method_name])?;
        value_to_bool(result)
    }

    // ========== Meterpreter Filesystem Operations ==========

    /// Get current working directory (pwd)
    /// Only works on Meterpreter sessions
    pub fn fs_pwd(&self) -> Result<String> {
        value_to_string(call_method(self.fs_dir_ext()?, "pwd", &[])?)
    }

    /// Change working directory (chdir)
    /// Only works on Meterpreter sessions
    pub fn fs_chdir(&self, path: &str) -> Result<()> {
        call_method(self.fs_dir_ext()?, "chdir", &[to_ruby_str(path)?])?;
        Ok(())
    }

    /// List directory contents
    /// Returns list of filenames (strings)
    /// Only works on Meterpreter sessions
    pub fn fs_ls(&self, path: &str) -> Result<Vec<String>> {
        let entries = call_method(self.fs_dir_ext()?, "entries", &[to_ruby_str(path)?])?;
        ruby_array_to_strings(entries)
    }

    /// Create directory
    /// Only works on Meterpreter sessions
    pub fn fs_mkdir(&self, path: &str) -> Result<()> {
        call_method(self.fs_dir_ext()?, "mkdir", &[to_ruby_str(path)?])?;
        Ok(())
    }

    /// Remove directory (must be empty)
    /// Only works on Meterpreter sessions
    pub fn fs_rmdir(&self, path: &str) -> Result<()> {
        call_method(self.fs_dir_ext()?, "rmdir", &[to_ruby_str(path)?])?;
        Ok(())
    }

    /// Get file/directory metadata (stat)
    /// Returns JSON with file info: size, ftype, mtime, is_file, is_directory
    /// Only works on Meterpreter sessions
    pub fn fs_stat(&self, path: &str) -> Result<serde_json::Value> {
        let stat_val = call_method(self.fs_file_ext()?, "stat", &[to_ruby_str(path)?])?;

        // Extract stat attributes
        let mut stat_obj = serde_json::Map::new();

        // Size
        if let Ok(size_val) = call_method(stat_val, "size", &[]) {
            let size: i64 = TryConvert::try_convert(size_val).unwrap_or(0);
            stat_obj.insert("size".to_string(), serde_json::json!(size));
        }

        // File type
        if let Ok(ftype_val) = call_method(stat_val, "ftype", &[]) {
            if let Ok(ftype) = value_to_string(ftype_val) {
                stat_obj.insert("ftype".to_string(), serde_json::json!(ftype));
            }
        }

        // Modified time
        if let Ok(mtime_val) = call_method(stat_val, "mtime", &[]) {
            if let Ok(mtime_str) = value_to_string(call_method(mtime_val, "to_s", &[])?) {
                stat_obj.insert("mtime".to_string(), serde_json::json!(mtime_str));
            }
        }

        // Check type predicates
        if let Ok(is_file_val) = call_method(stat_val, "file?", &[]) {
            if let Ok(is_file) = value_to_bool(is_file_val) {
                stat_obj.insert("is_file".to_string(), serde_json::json!(is_file));
            }
        }

        if let Ok(is_dir_val) = call_method(stat_val, "directory?", &[]) {
            if let Ok(is_dir) = value_to_bool(is_dir_val) {
                stat_obj.insert("is_directory".to_string(), serde_json::json!(is_dir));
            }
        }

        Ok(serde_json::Value::Object(stat_obj))
    }

    /// Check if file/directory exists
    /// Only works on Meterpreter sessions
    pub fn fs_exists(&self, path: &str) -> Result<bool> {
        let exists_val = call_method(self.fs_file_ext()?, "exist?", &[to_ruby_str(path)?])?;
        value_to_bool(exists_val)
    }

    /// Delete file
    /// Only works on Meterpreter sessions
    pub fn fs_rm(&self, path: &str) -> Result<()> {
        call_method(self.fs_file_ext()?, "rm", &[to_ruby_str(path)?])?;
        Ok(())
    }

    /// Move/rename file
    /// Only works on Meterpreter sessions
    pub fn fs_mv(&self, old_path: &str, new_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "mv",
            &[to_ruby_str(old_path)?, to_ruby_str(new_path)?],
        )?;
        Ok(())
    }

    /// Copy file
    /// Only works on Meterpreter sessions
    pub fn fs_cp(&self, src_path: &str, dst_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "cp",
            &[to_ruby_str(src_path)?, to_ruby_str(dst_path)?],
        )?;
        Ok(())
    }

    /// Get path separator for target system
    /// Returns "\\" on Windows, "/" on Unix
    /// Only works on Meterpreter sessions
    pub fn fs_separator(&self) -> Result<String> {
        value_to_string(call_method(self.fs_file_ext()?, "separator", &[])?)
    }

    /// Expand path (resolve environment variables like %appdata%, $HOME)
    /// Only works on Meterpreter sessions
    pub fn fs_expand_path(&self, path: &str) -> Result<String> {
        value_to_string(call_method(
            self.fs_file_ext()?,
            "expand_path",
            &[to_ruby_str(path)?],
        )?)
    }

    /// Download file from remote to local
    /// Only works on Meterpreter sessions
    pub fn fs_download_file(&self, local_path: &str, remote_path: &str) -> Result<String> {
        let status_val = call_method(
            self.fs_file_ext()?,
            "download_file",
            &[to_ruby_str(local_path)?, to_ruby_str(remote_path)?],
        )?;
        // download_file returns status string: "Completed", "Skipped", etc.
        value_to_string(status_val)
    }

    /// Upload file from local to remote
    /// Only works on Meterpreter sessions
    pub fn fs_upload_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "upload_file",
            &[to_ruby_str(remote_path)?, to_ruby_str(local_path)?],
        )?;
        Ok(())
    }

    // ========== Post Module Execution ==========

    /// Run a post module on this session
    ///
    /// This is used for post-exploitation tasks like:
    /// - Upgrading shell to meterpreter (post/multi/manage/shell_to_meterpreter)
    /// - Gathering credentials
    /// - Privilege escalation
    /// - Persistence
    ///
    /// The module will automatically have its SESSION datastore option set to this session.
    pub fn run_post_module(
        &self,
        module_path: &str,
        options: std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Get framework
        let framework = crate::ruby_bridge::create_framework(None)?;

        // Get modules
        let modules = call_method(framework, "modules", &[])?;

        // Create the post module
        let module_name = ruby.str_new(module_path).as_value();
        let module = call_method(modules, "create", &[module_name])?;

        if is_nil(module) {
            return Err(AssassinateError::ModuleNotFound(module_path.to_string()));
        }

        // Set SESSION datastore option to this session's ID
        let datastore = call_method(module, "datastore", &[])?;
        call_method(
            datastore,
            "[]=",
            &[
                ruby.str_new("SESSION").as_value(),
                ruby.integer_from_i64(self.session_id).as_value(),
            ],
        )?;

        // Set additional options
        for (key, value) in options {
            let key_val = ruby.str_new(&key).as_value();
            let value_val = ruby.str_new(&value).as_value();
            call_method(datastore, "[]=", &[key_val, value_val])?;
        }

        // Run the module
        let result = call_method(module, "run", &[])?;

        // Check if nil (failure) or has a value (success)
        Ok(!is_nil(result))
    }

    // ========== Process Management (Meterpreter) ==========

    /// Get the current process ID (getpid)
    /// Only works on Meterpreter sessions
    pub fn process_getpid(&self) -> Result<i64> {
        let pid_val = call_method(self.sys_process()?, "getpid", &[])?;
        crate::ruby_bridge::value_to_i64(pid_val)
    }

    /// List all running processes
    /// Returns Vec of JSON objects with keys: pid, ppid, name, path, user, session, arch
    /// Only works on Meterpreter sessions
    pub fn process_list(&self) -> Result<Vec<serde_json::Value>> {
        let processes = call_method(self.sys_process()?, "get_processes", &[])?;
        let len = crate::ruby_bridge::ruby_array_len(processes)?;

        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let process = crate::ruby_bridge::ruby_array_get(processes, i)?;
            let process_json = crate::ruby_bridge::hash_to_json(process)?;
            result.push(process_json);
        }

        Ok(result)
    }

    /// Kill a process by PID
    /// Only works on Meterpreter sessions
    pub fn process_kill(&self, pid: i64) -> Result<()> {
        call_method(
            self.sys_process()?,
            "kill",
            &[crate::ruby_bridge::to_ruby_int(pid)?],
        )?;
        Ok(())
    }

    /// Execute a command and return the process info
    /// Returns JSON with: pid, handle, channel_id (if channelized)
    /// Only works on Meterpreter sessions
    pub fn process_execute(
        &self,
        path: &str,
        args: &str,
        hidden: bool,
        channelized: bool,
    ) -> Result<serde_json::Value> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_hash = ruby.hash_new();
        if hidden {
            call_method(
                opts_hash.as_value(),
                "[]=",
                &[to_ruby_str("Hidden")?, ruby.qtrue().as_value()],
            )?;
        }
        if channelized {
            call_method(
                opts_hash.as_value(),
                "[]=",
                &[to_ruby_str("Channelized")?, ruby.qtrue().as_value()],
            )?;
        }

        // Execute: sys.process.execute(path, args, opts)
        let process_val = call_method(
            self.sys_process()?,
            "execute",
            &[to_ruby_str(path)?, to_ruby_str(args)?, opts_hash.as_value()],
        )?;

        // Extract pid from process object
        let pid_val = call_method(process_val, "pid", &[])?;
        let pid = crate::ruby_bridge::value_to_i64(pid_val)?;

        // Extract handle
        let handle_val = call_method(process_val, "handle", &[])?;
        let handle = if is_nil(handle_val) {
            0
        } else {
            crate::ruby_bridge::value_to_i64(handle_val).unwrap_or(0)
        };

        // Extract channel if it exists
        let channel_val = call_method(process_val, "channel", &[])?;
        let channel_id = if is_nil(channel_val) {
            None
        } else {
            // Get channel ID from channel object
            let cid_val = call_method(channel_val, "cid", &[])?;
            Some(crate::ruby_bridge::value_to_i64(cid_val).unwrap_or(0))
        };

        Ok(serde_json::json!({
            "pid": pid,
            "handle": handle,
            "channel_id": channel_id,
        }))
    }
}

/// Database manager
#[derive(Clone)]
pub struct DbManager {
    pub(crate) ruby_db: Value,
}

impl DbManager {
    /// Get all hosts
    pub fn hosts(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // MSF hosts() returns an ActiveRecord relation of Mdm::Host objects
        // We need to convert each host to a string representation (IP address)
        let hosts_val = call_method(self.ruby_db, "hosts", &[])?;

        // Check if nil (database might be empty or not configured)
        if is_nil(hosts_val) {
            return Ok(Vec::new());
        }

        // Convert to array by calling to_a on the relation, then map to get addresses
        let hosts_array = call_method(hosts_val, "to_a", &[])?;
        let hosts_len: i64 =
            TryConvert::try_convert(call_method(hosts_array, "length", &[])?).unwrap_or(0);

        let mut result = Vec::new();
        for i in 0..hosts_len {
            let idx_val = ruby.integer_from_i64(i).as_value();
            let host_obj = call_method(hosts_array, "[]", &[idx_val])?;
            // Get the address attribute from the Mdm::Host object
            let addr = call_method(host_obj, "address", &[])?;
            if let Ok(addr_str) = value_to_string(addr) {
                result.push(addr_str);
            }
        }

        Ok(result)
    }

    /// Get all services
    pub fn services(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        let services_val = call_method(self.ruby_db, "services", &[])?;

        // Check if nil (database might be empty or not configured)
        if is_nil(services_val) {
            return Ok(Vec::new());
        }

        // Convert to array - MSF returns Mdm::Service objects
        let services_array = call_method(services_val, "to_a", &[])?;
        let services_len: i64 =
            TryConvert::try_convert(call_method(services_array, "length", &[])?).unwrap_or(0);

        let mut result = Vec::new();
        for i in 0..services_len {
            let idx_val = ruby.integer_from_i64(i).as_value();
            let service_obj = call_method(services_array, "[]", &[idx_val])?;
            // Get host address and port from service object
            let host_obj = call_method(service_obj, "host", &[])?;
            let host_addr = call_method(host_obj, "address", &[])?;
            let port = call_method(service_obj, "port", &[])?;
            let proto = call_method(service_obj, "proto", &[])?;

            if let (Ok(host_str), Ok(port_str), Ok(proto_str)) = (
                value_to_string(host_addr),
                value_to_string(port),
                value_to_string(proto),
            ) {
                result.push(format!("{}:{}/{}", host_str, port_str, proto_str));
            }
        }

        Ok(result)
    }

    /// Report a host to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with host parameters (e.g., "host", "os_name", "os_flavor")
    ///
    /// # Returns
    /// Returns the host ID from the database
    pub fn report_host(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_host", opts)
    }

    /// Report a service to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with service parameters (e.g., "host", "port", "proto", "name")
    ///
    /// # Returns
    /// Returns the service ID from the database
    pub fn report_service(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_service", opts)
    }

    /// Report a vulnerability to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with vulnerability parameters (e.g., "host", "name", "info")
    ///
    /// # Returns
    /// Returns the vulnerability ID from the database
    pub fn report_vuln(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_vuln", opts)
    }

    /// Report a credential to the database
    ///
    /// This method automatically handles workspace injection via the ASSASSINATE_WORKSPACE
    /// environment variable (defaults to "default"). The workspace is found or created
    /// automatically, ensuring the credential is always reported in a valid workspace context.
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with credential parameters (e.g., "host", "port", "user", "pass")
    ///
    /// # Returns
    /// Returns the credential ID from the database
    ///
    /// # Environment Variables
    /// * `ASSASSINATE_WORKSPACE` - Workspace name to use (defaults to "default" if not set)
    pub fn report_cred(&self, opts: Option<HashMap<String, String>>) -> Result<i64> {
        self.report_to_db("report_cred", opts)
    }

    /// Get all vulnerabilities
    pub fn vulns(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // MSF vulns() expects a workspace parameter, use empty hash for default workspace
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        let vulns_val = call_method(self.ruby_db, "vulns", &[opts_val])?;

        // Check if nil (database might be empty or not configured)
        if is_nil(vulns_val) {
            return Ok(Vec::new());
        }

        // Convert to array - MSF returns Mdm::Vuln objects
        let vulns_array = call_method(vulns_val, "to_a", &[])?;
        let vulns_len: i64 =
            TryConvert::try_convert(call_method(vulns_array, "length", &[])?).unwrap_or(0);

        let mut result = Vec::new();
        for i in 0..vulns_len {
            let idx_val = ruby.integer_from_i64(i).as_value();
            let vuln_obj = call_method(vulns_array, "[]", &[idx_val])?;
            // Get vuln name from object
            let name = call_method(vuln_obj, "name", &[])?;
            if let Ok(name_str) = value_to_string(name) {
                result.push(name_str);
            }
        }

        Ok(result)
    }

    /// Get all credentials
    pub fn creds(&self) -> Result<Vec<String>> {
        let creds_val = call_method(self.ruby_db, "creds", &[])?;

        // Check if nil (database might be empty or not configured)
        if is_nil(creds_val) {
            return Ok(Vec::new());
        }

        // Convert to array of strings
        let creds: Vec<String> =
            TryConvert::try_convert(creds_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert creds: {}", e))
            })?;

        Ok(creds)
    }

    /// Get all loot
    pub fn loot(&self) -> Result<Vec<String>> {
        let loot_val = call_method(self.ruby_db, "loot", &[])?;

        // Check if nil (database might be empty or not configured)
        if is_nil(loot_val) {
            return Ok(Vec::new());
        }

        // Convert to array of strings
        let loot: Vec<String> = TryConvert::try_convert(loot_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert loot: {}", e))
        })?;

        Ok(loot)
    }

    /// Helper function to report to database (reduces code duplication)
    ///
    /// This unified helper handles all database reporting operations and automatically
    /// injects workspace context for methods that require it (like report_cred).
    ///
    /// # Arguments
    /// * `method_name` - The MSF database method to call (e.g., "report_host", "report_cred")
    /// * `opts` - Optional HashMap of parameters to pass to the method
    ///
    /// # Workspace Handling
    /// For `report_cred`, this method automatically:
    /// 1. Reads ASSASSINATE_WORKSPACE environment variable (defaults to "default")
    /// 2. Finds or creates the workspace using find_workspace/add_workspace
    /// 3. Injects the workspace object into the options hash
    ///
    /// This ensures report_cred always has a valid workspace context, which MSF requires.
    fn report_to_db(
        &self,
        method_name: &str,
        opts: Option<HashMap<String, String>>,
    ) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys (MSF expects symbol keys like :host, not string keys)
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                // Convert string key to symbol using intern
                let key_sym = StaticSymbol::new(key);
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_sym.as_value(), value_val])?;
            }
        }

        // Special handling for report_cred: MSF requires :workspace parameter
        // See: https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/db_manager/cred.rb
        // Per Msf::Util::DBManager.process_opts_workspace, workspace can be:
        // - A String (workspace name) - but this is less reliable
        // - An Mdm::Workspace object - recommended approach
        // - A Hash with :name key
        if method_name == "report_cred" {
            // Get workspace name from environment or use default
            let workspace_name =
                std::env::var("ASSASSINATE_WORKSPACE").unwrap_or_else(|_| "default".to_string());

            // Find existing workspace
            let mut workspace_obj = call_method(
                self.ruby_db,
                "find_workspace",
                &[ruby.str_new(&workspace_name).as_value()],
            )?;

            // If workspace doesn't exist, create it
            if is_nil(workspace_obj) {
                let add_opts = ruby.eval::<Value>("{}").map_err(|e| {
                    AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
                })?;
                let name_sym = StaticSymbol::new("name");
                call_method(
                    add_opts,
                    "[]=",
                    &[
                        name_sym.as_value(),
                        ruby.str_new(&workspace_name).as_value(),
                    ],
                )?;
                workspace_obj = call_method(self.ruby_db, "add_workspace", &[add_opts])?;
            }

            // Inject workspace object into options hash
            let workspace_sym = StaticSymbol::new("workspace");
            call_method(opts_val, "[]=", &[workspace_sym.as_value(), workspace_obj])?;
        }

        let result_val = call_method(self.ruby_db, method_name, &[opts_val])?;
        let id: i64 = TryConvert::try_convert(result_val).unwrap_or(0);
        Ok(id)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok("<DbManager>".to_string())
    }
}

/// Job manager
#[derive(Clone)]
pub struct JobManager {
    pub(crate) ruby_jobs: Value,
}

impl JobManager {
    /// List all job IDs
    pub fn list(&self) -> Result<Vec<String>> {
        let keys_val = call_method(self.ruby_jobs, "keys", &[])?;

        let job_ids: Vec<String> =
            TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert job IDs: {}", e))
            })?;

        Ok(job_ids)
    }

    /// Get job by ID
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
    pub fn kill(&self, job_id: &str) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        match call_method(self.ruby_jobs, "stop", &[id_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get job by ID (raw version without PyO3)
    pub fn get_raw(&self, job_id: &str) -> Result<Option<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        let job_val = call_method(self.ruby_jobs, "[]", &[id_val])?;

        if is_nil(job_val) {
            Ok(None)
        } else {
            Ok(Some(value_to_string(job_val)?))
        }
    }

    /// Kill a job by ID (raw version without PyO3)
    pub fn kill_raw(&self, job_id: &str) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        match call_method(self.ruby_jobs, "stop", &[id_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<JobManager jobs={}>", self.list()?.len()))
    }
}

/// Plugin manager
#[derive(Clone)]
pub struct PluginManager {
    pub(crate) ruby_plugins: Value,
}

impl PluginManager {
    /// List loaded plugins
    pub fn list(&self) -> Result<Vec<String>> {
        // PluginManager is an array of plugin instances
        // Call to_a to convert to array
        let plugins_array: magnus::RArray =
            TryConvert::try_convert(self.ruby_plugins).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert plugins to array: {}",
                    e
                ))
            })?;

        let mut plugin_names = Vec::new();
        for plugin_val in plugins_array.into_iter() {
            // Get plugin name
            let name_val = call_method(plugin_val, "name", &[])?;
            let name = value_to_string(name_val)?;
            plugin_names.push(name);
        }

        Ok(plugin_names)
    }

    /// List loaded plugins (raw version without PyO3)
    pub fn list_raw(&self) -> Result<Vec<String>> {
        self.list()
    }

    /// Load a plugin from path
    pub fn load_raw(&self, path: &str, options: Option<HashMap<String, String>>) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_val = ruby.eval::<Value>("{}").map_err(|e| {
            AssassinateError::ConversionError(format!("Failed to create hash: {}", e))
        })?;

        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = ruby.str_new(&value).as_value();
                call_method(opts_val, "[]=", &[key_val, value_val])?;
            }
        }

        // Load the plugin
        let path_val = ruby.str_new(path).as_value();
        let plugin_instance = call_method(self.ruby_plugins, "load", &[path_val, opts_val])?;

        // Get plugin name
        let name_val = call_method(plugin_instance, "name", &[])?;
        let name = value_to_string(name_val)?;

        Ok(name)
    }

    /// Unload a plugin by name
    pub fn unload_raw(&self, plugin_name: &str) -> Result<bool> {
        // PluginManager is an array, so we need to find the plugin by name
        let plugins_array: magnus::RArray =
            TryConvert::try_convert(self.ruby_plugins).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert plugins to array: {}",
                    e
                ))
            })?;

        // Find plugin instance by name
        for plugin_val in plugins_array.into_iter() {
            let name_val = call_method(plugin_val, "name", &[])?;
            let name = value_to_string(name_val)?;

            if name == plugin_name {
                // Found it, unload it
                call_method(self.ruby_plugins, "unload", &[plugin_val])?;
                return Ok(true);
            }
        }

        // Plugin not found
        Ok(false)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<PluginManager plugins={}>", self.list()?.len()))
    }
}

#[derive(Clone)]
pub struct PayloadGenerator {
    ruby_framework: Value,
}

impl PayloadGenerator {
    pub fn new(framework: &Framework) -> Result<Self> {
        Ok(PayloadGenerator {
            ruby_framework: framework.ruby_framework,
        })
    }

    /// Generate a payload
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
        let rstring: magnus::RString =
            TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert payload to RString: {}",
                    e
                ))
            })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    /// Generate a payload and encode it
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
        let rstring: magnus::RString =
            TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert payload to RString: {}",
                    e
                ))
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
        let exe_module: Value = ruby.eval("Msf::Util::EXE").map_err(|e| {
            AssassinateError::RubyError(format!("Failed to get Msf::Util::EXE: {}", e))
        })?;

        // Call to_executable with the payload's own arch/platform
        // These are already in the correct format (arrays of constants)
        let exe: Value = exe_module
            .funcall(
                "to_executable",
                (
                    self.ruby_framework,
                    payload_arch,
                    payload_platform,
                    raw_payload,
                    opts,
                ),
            )
            .map_err(|e| AssassinateError::RubyError(format!("to_executable failed: {}", e)))?;

        if is_nil(exe) {
            return Err(AssassinateError::PayloadError(format!(
                "to_executable returned nil for arch={}, platform={}",
                arch, platform
            )));
        }

        // Convert Ruby binary string to bytes
        let rstring: magnus::RString =
            TryConvert::try_convert(exe).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert executable to RString: {}. Value type: {:?}",
                    e, exe
                ))
            })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok("<PayloadGenerator>".to_string())
    }
}
