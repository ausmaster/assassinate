//! Metasploit module types and operations

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{
    build_quiet_opts, call_method, get_bool_attr, get_string_attr, is_nil, value_to_string,
};
use magnus::{value::ReprValue, TryConvert, Value};
use std::collections::HashMap;

use super::DataStore;

/// Metasploit module instance
#[derive(Clone)]
pub struct Module {
    pub(crate) ruby_module: Value,
}

impl Module {
    /// Get module name
    pub fn name(&self) -> Result<String> {
        get_string_attr(self.ruby_module, "name")
    }

    /// Get module full name
    pub fn fullname(&self) -> Result<String> {
        get_string_attr(self.ruby_module, "fullname")
    }

    /// Get module description
    pub fn description(&self) -> Result<String> {
        get_string_attr(self.ruby_module, "description")
    }

    /// Get module type
    pub fn module_type(&self) -> Result<String> {
        get_string_attr(self.ruby_module, "type")
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
        let opts_val = build_quiet_opts(options)?;

        // Call run_simple on the module
        match call_method(self.ruby_module, "run_simple", &[opts_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if target is vulnerable
    /// Returns check result code as string
    pub fn check(&self) -> Result<String> {
        let opts_val = build_quiet_opts(None)?;

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
                let array_len: usize = TryConvert::try_convert(call_method(
                    payloads_val,
                    "length",
                    &[],
                )?)
                .map_err(|e: magnus::Error| {
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
                let array_len: usize = TryConvert::try_convert(call_method(
                    actions_val,
                    "length",
                    &[],
                )?)
                .map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!(
                        "Failed to get actions array length: {}",
                        e
                    ))
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
        get_string_attr(self.ruby_module, "options")
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
        get_string_attr(self.ruby_module, "rank")
    }

    /// Check if module requires privileged access
    pub fn privileged(&self) -> Result<bool> {
        get_bool_attr(self.ruby_module, "privileged")
    }

    /// Get module license
    pub fn license(&self) -> Result<String> {
        get_string_attr(self.ruby_module, "license")
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
