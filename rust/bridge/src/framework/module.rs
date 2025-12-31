//! Metasploit module types and operations

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{
    build_opts, call_method, get_bool_attr, get_string_attr, responds_to_public, sym,
    value_to_string, Options, RubyVal,
};
use magnus::{value::ReprValue, RArray, TryConvert, Value};
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
    ///
    /// # Options
    /// Use RubyVal for type-safe option values:
    /// * `Quiet` - RubyVal::Bool(true) to suppress output (recommended)
    /// * `RunAsJob` - RubyVal::Bool(true) to run as background job (for handlers)
    /// * `ForceBlocking` - RubyVal::Bool(true) to wait for session (default if RunAsJob not set)
    pub fn exploit(&self, payload: &str, options: Option<Options>) -> Result<Option<i64>> {
        // Check if RunAsJob is explicitly set
        let run_as_job = options
            .as_ref()
            .and_then(|opts| opts.get("RunAsJob"))
            .map(|v| matches!(v, RubyVal::Bool(true)))
            .unwrap_or(false);

        // Build options, adding defaults
        let mut opts = options.unwrap_or_default();
        opts.insert("Payload".into(), RubyVal::String(payload.to_string()));
        opts.entry("Quiet".into()).or_insert(RubyVal::Bool(true));

        // If not running as job, set ForceBlocking to wait for session
        if !run_as_job {
            opts.entry("ForceBlocking".into())
                .or_insert(RubyVal::Bool(true));
        }

        let opts_val = build_opts(Some(opts))?;

        // Call exploit_simple on the module
        let session_val = call_method(self.ruby_module, "exploit_simple", &[opts_val])?;

        if session_val.is_nil() {
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
    pub fn run(&self, options: Option<Options>) -> Result<bool> {
        let mut opts = options.unwrap_or_default();
        opts.entry("Quiet".into()).or_insert(RubyVal::Bool(true));
        let opts_val = build_opts(Some(opts))?;

        // Call run_simple on the module
        match call_method(self.ruby_module, "run_simple", &[opts_val]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if target is vulnerable
    /// Returns check result code as string
    pub fn check(&self) -> Result<String> {
        let mut opts = Options::new();
        opts.insert("Quiet".into(), RubyVal::Bool(true));
        let opts_val = build_opts(Some(opts))?;

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
        Ok(result.to_bool())
    }

    /// Get available payloads for this exploit
    pub fn compatible_payloads(&self) -> Result<Vec<String>> {
        // Check if module responds to compatible_payloads using Magnus built-in
        if !responds_to_public(self.ruby_module, "compatible_payloads") {
            return Ok(vec![]);
        }

        // Get compatible payloads - returns array of [name, class] tuples
        let payloads_val = call_method(self.ruby_module, "compatible_payloads", &[])?;

        // Use RArray for efficient array access
        let payloads_array = RArray::from_value(payloads_val).ok_or_else(|| {
            AssassinateError::ConversionError("compatible_payloads did not return an array".into())
        })?;

        // Iterate through array and extract first element (payload name) from each tuple
        let mut result = Vec::with_capacity(payloads_array.len());
        for i in 0..payloads_array.len() {
            // Get the [name, class] tuple
            let tuple_val: Value = payloads_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get tuple at {}: {}", i, e))
            })?;

            // Use RArray to get first element efficiently
            if let Some(tuple_array) = RArray::from_value(tuple_val) {
                let name_val: Value = tuple_array.entry(0).map_err(|e| {
                    AssassinateError::ConversionError(format!("Failed to get name from tuple: {}", e))
                })?;
                result.push(value_to_string(name_val)?);
            }
        }

        Ok(result)
    }

    /// Get available actions for this auxiliary/post module
    /// Returns list of action names
    pub fn actions(&self) -> Result<Vec<String>> {
        // Check if module responds to actions using Magnus built-in
        if !responds_to_public(self.ruby_module, "actions") {
            return Ok(vec![]);
        }

        // Get actions array
        let actions_val = call_method(self.ruby_module, "actions", &[])?;

        // Use RArray for efficient array access
        let actions_array = RArray::from_value(actions_val).ok_or_else(|| {
            AssassinateError::ConversionError("actions did not return an array".into())
        })?;

        // Iterate through actions and extract names
        let mut result = Vec::with_capacity(actions_array.len());
        for i in 0..actions_array.len() {
            let action_val: Value = actions_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get action at {}: {}", i, e))
            })?;
            // Use LazyId for efficient method call (dereference to get OpaqueId)
            let name_val: Value = action_val.funcall(*sym::NAME, ()).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to get action name: {}", e))
            })?;
            result.push(value_to_string(name_val)?);
        }

        Ok(result)
    }

    /// Get the default action for this auxiliary/post module
    /// Returns None if module doesn't support actions or has no default
    pub fn default_action(&self) -> Result<Option<String>> {
        // Check if module responds to default_action using Magnus built-in
        if !responds_to_public(self.ruby_module, "default_action") {
            return Ok(None);
        }

        let default_val = call_method(self.ruby_module, "default_action", &[])?;

        if default_val.is_nil() {
            Ok(None)
        } else {
            Ok(Some(value_to_string(default_val)?))
        }
    }

    /// Get the current action for this auxiliary/post module
    /// This looks up datastore['ACTION'] and returns the matching action name
    /// Falls back to default_action if ACTION is not set
    /// Returns None if module doesn't support actions
    pub fn action(&self) -> Result<Option<String>> {
        // Check if module responds to action using Magnus built-in
        if !responds_to_public(self.ruby_module, "action") {
            return Ok(None);
        }

        let action_val = call_method(self.ruby_module, "action", &[])?;

        if action_val.is_nil() {
            Ok(None)
        } else {
            // action returns an AuxiliaryAction object, get its name using LazyId
            let name_val: Value = action_val.funcall(*sym::NAME, ()).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to get action name: {}", e))
            })?;
            Ok(Some(value_to_string(name_val)?))
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
        if platform_val.is_nil() {
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
        if arch_val.is_nil() {
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
        // Check if module responds to targets using Magnus built-in
        if !responds_to_public(self.ruby_module, "targets") {
            return Ok(vec![]);
        }

        let targets_val = call_method(self.ruby_module, "targets", &[])?;

        if targets_val.is_nil() {
            return Ok(vec![]);
        }

        // Use RArray for efficient array access
        let targets_array = RArray::from_value(targets_val).ok_or_else(|| {
            AssassinateError::ConversionError("targets did not return an array".into())
        })?;

        // Extract name from each target object using StaticSymbol
        let mut target_names = Vec::with_capacity(targets_array.len());
        for i in 0..targets_array.len() {
            let target_obj: Value = targets_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get target at {}: {}", i, e))
            })?;
            let name_val: Value = target_obj.funcall(*sym::NAME, ()).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to get target name: {}", e))
            })?;
            target_names.push(value_to_string(name_val)?);
        }

        Ok(target_names)
    }

    /// Get vulnerability disclosure date
    pub fn disclosure_date(&self) -> Result<Option<String>> {
        let date_val = call_method(self.ruby_module, "disclosure_date", &[])?;

        if date_val.is_nil() {
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

        if notes_val.is_nil() {
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

    // ========== Module Option Validation ==========

    /// Get structured options with full details (type, required, default, description)
    pub fn options_structured(&self) -> Result<HashMap<String, serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let options_val = call_method(self.ruby_module, "options", &[])?;

        if options_val.is_nil() {
            return Ok(HashMap::new());
        }

        // Get option names
        let keys_val = call_method(options_val, "keys", &[])?;
        let keys: Vec<String> = TryConvert::try_convert(keys_val)
            .map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to get option keys: {}", e))
            })?;

        let mut structured_options = HashMap::new();

        // Iterate through each option and extract attributes
        for opt_name in keys {
            let opt_name_val = ruby.str_new(&opt_name).as_value();
            let opt_obj = call_method(options_val, "[]", &[opt_name_val])?;

            if opt_obj.is_nil() {
                continue;
            }

            let mut opt_details = serde_json::Map::new();

            // Extract required attribute
            if let Ok(required_val) = call_method(opt_obj, "required", &[]) {
                let required_bool = required_val.to_bool();
                opt_details.insert("required".to_string(), serde_json::json!(required_bool));
            }

            // Extract description
            if let Ok(desc_val) = call_method(opt_obj, "desc", &[]) {
                if !desc_val.is_nil() {
                    if let Ok(desc_str) = value_to_string(desc_val) {
                        opt_details.insert("desc".to_string(), serde_json::json!(desc_str));
                    }
                }
            }

            // Extract default value
            if let Ok(default_val) = call_method(opt_obj, "default", &[]) {
                if default_val.is_nil() {
                    opt_details.insert("default".to_string(), serde_json::Value::Null);
                } else if let Ok(default_str) = value_to_string(default_val) {
                    opt_details.insert("default".to_string(), serde_json::json!(default_str));
                }
            }

            // Extract type (class name)
            if let Ok(type_val) = call_method(opt_obj, "type", &[]) {
                if !type_val.is_nil() {
                    if let Ok(type_str) = value_to_string(type_val) {
                        opt_details.insert("type".to_string(), serde_json::json!(type_str));
                    }
                }
            }

            structured_options.insert(opt_name, serde_json::Value::Object(opt_details));
        }

        Ok(structured_options)
    }

    /// Get list of missing required options
    pub fn missing_required(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let options_val = call_method(self.ruby_module, "options", &[])?;

        if options_val.is_nil() {
            return Ok(Vec::new());
        }

        let mut missing = Vec::new();

        // Get option names
        let keys_val = call_method(options_val, "keys", &[])?;
        let keys: Vec<String> = TryConvert::try_convert(keys_val)
            .map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to get option keys: {}", e))
            })?;

        // Get datastore once
        let datastore_val = call_method(self.ruby_module, "datastore", &[])?;

        // Iterate through each option
        for opt_name in keys {
            let opt_name_val = ruby.str_new(&opt_name).as_value();
            let opt_obj = call_method(options_val, "[]", &[opt_name_val])?;

            if opt_obj.is_nil() {
                continue;
            }

            // Check if required
            let is_required = match call_method(opt_obj, "required", &[]) {
                Ok(required_val) => required_val.to_bool(),
                Err(_) => false,
            };

            if is_required {
                // Check if the option has a value set in the module's datastore
                let current_val = call_method(datastore_val, "[]", &[opt_name_val])?;

                // If nil or empty string, it's missing
                if current_val.is_nil() {
                    missing.push(opt_name);
                } else if let Ok(val_str) = value_to_string(current_val) {
                    if val_str.is_empty() {
                        missing.push(opt_name);
                    }
                }
            }
        }

        Ok(missing)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Module name='{}' type='{}'>",
            self.fullname()?,
            self.module_type()?
        ))
    }
}
