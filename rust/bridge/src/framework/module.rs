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

    /// Get the framework instance this module belongs to
    pub fn framework(&self) -> Result<super::Framework> {
        let fw_val = call_method(self.ruby_module, "framework", &[])?;
        Ok(super::Framework {
            ruby_framework: fw_val,
        })
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
        // CRITICAL: Set PAYLOAD in the module's datastore, not just the options hash.
        // MSF's exploit_simple checks datastore['PAYLOAD'] for target validation.
        self.set_option("PAYLOAD", payload)?;

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

        // Handle all failure cases: nil, false, or non-session objects
        // In Ruby: nil and false are falsy, everything else is truthy
        if session_val.is_nil() {
            return Ok(None);
        }
        // Check if the value is falsy (Ruby false)
        let is_falsy: bool = TryConvert::try_convert(session_val).unwrap_or(false);
        if is_falsy {
            return Ok(None);
        }

        // Check if it's actually a session object before calling sid
        let responds_to_sid = responds_to_public(session_val, "sid");
        if !responds_to_sid {
            return Ok(None);
        }

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

        // author is an array of Author objects - must call to_s on each
        let author_array = RArray::from_value(author_val).ok_or_else(|| {
            AssassinateError::ConversionError("author did not return an array".into())
        })?;

        let mut authors = Vec::with_capacity(author_array.len());
        for i in 0..author_array.len() {
            let author_obj: Value = author_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get author at {}: {}", i, e))
            })?;
            authors.push(value_to_string(author_obj)?);
        }

        Ok(authors)
    }

    /// Get module references (CVE, BID, URL, etc.)
    pub fn references(&self) -> Result<Vec<String>> {
        let refs_val = call_method(self.ruby_module, "references", &[])?;

        // References is an array of Ref objects - must call to_s on each
        let refs_array = RArray::from_value(refs_val).ok_or_else(|| {
            AssassinateError::ConversionError("references did not return an array".into())
        })?;

        let mut refs = Vec::with_capacity(refs_array.len());
        for i in 0..refs_array.len() {
            let ref_obj: Value = refs_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get reference at {}: {}", i, e))
            })?;
            refs.push(value_to_string(ref_obj)?);
        }

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

        // Platform is a PlatformList - call .names to get array of platform names
        let names_val = call_method(platform_val, "names", &[])?;

        let names_array = RArray::from_value(names_val).ok_or_else(|| {
            AssassinateError::ConversionError("platform.names did not return an array".into())
        })?;

        let mut platforms = Vec::with_capacity(names_array.len());
        for i in 0..names_array.len() {
            let name_val: Value = names_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get platform name at {}: {}", i, e))
            })?;
            platforms.push(value_to_string(name_val)?);
        }

        Ok(platforms)
    }

    /// Get module target architectures
    pub fn arch(&self) -> Result<Vec<String>> {
        let arch_val = call_method(self.ruby_module, "arch", &[])?;

        // Arch can be an array or nil
        if arch_val.is_nil() {
            return Ok(vec![]);
        }

        // Arch is an array - must call to_s on each element
        let arch_array = RArray::from_value(arch_val).ok_or_else(|| {
            AssassinateError::ConversionError("arch did not return an array".into())
        })?;

        let mut archs = Vec::with_capacity(arch_array.len());
        for i in 0..arch_array.len() {
            let arch_obj: Value = arch_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get arch at {}: {}", i, e))
            })?;
            archs.push(value_to_string(arch_obj)?);
        }

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

    // ========== Exploit Target Constraints (4.5C) ==========

    /// Get available payload space for the current target
    ///
    /// This returns the maximum size (in bytes) that the payload can be
    /// for the currently selected exploit target.
    pub fn payload_space(&self) -> Result<Option<i64>> {
        // Try target-specific payload_space first
        let target = self.current_target_obj()?;
        if !target.is_nil() {
            if let Ok(opts) = call_method(target, "opts", &[]) {
                if !opts.is_nil() {
                    let ruby = crate::ruby_bridge::get_ruby()?;
                    let key = ruby.str_new("Payload").as_value();
                    if let Ok(payload_opts) = call_method(opts, "[]", &[key]) {
                        if !payload_opts.is_nil() {
                            let space_key = ruby.str_new("Space").as_value();
                            if let Ok(space_val) = call_method(payload_opts, "[]", &[space_key]) {
                                if !space_val.is_nil() {
                                    let space: i64 = TryConvert::try_convert(space_val)
                                        .map_err(|e: magnus::Error| {
                                            AssassinateError::ConversionError(format!(
                                                "Failed to convert payload space: {}",
                                                e
                                            ))
                                        })?;
                                    return Ok(Some(space));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fall back to module's payload_space method
        if let Ok(space_val) = call_method(self.ruby_module, "payload_space", &[]) {
            if !space_val.is_nil() {
                let space: i64 = TryConvert::try_convert(space_val).map_err(|e: magnus::Error| {
                    AssassinateError::ConversionError(format!(
                        "Failed to convert payload space: {}",
                        e
                    ))
                })?;
                return Ok(Some(space));
            }
        }

        Ok(None)
    }

    /// Get bad characters that should be avoided in payloads for the current target
    ///
    /// Returns the bytes that cannot appear in the payload. These are typically
    /// characters that would break the exploit (e.g., null bytes, newlines).
    pub fn payload_badchars(&self) -> Result<Vec<u8>> {
        // Try target-specific badchars first
        let target = self.current_target_obj()?;
        if !target.is_nil() {
            if let Ok(opts) = call_method(target, "opts", &[]) {
                if !opts.is_nil() {
                    let ruby = crate::ruby_bridge::get_ruby()?;
                    let key = ruby.str_new("Payload").as_value();
                    if let Ok(payload_opts) = call_method(opts, "[]", &[key]) {
                        if !payload_opts.is_nil() {
                            let badchars_key = ruby.str_new("BadChars").as_value();
                            if let Ok(badchars_val) = call_method(payload_opts, "[]", &[badchars_key]) {
                                if !badchars_val.is_nil() {
                                    let rstring: magnus::RString = TryConvert::try_convert(badchars_val)
                                        .map_err(|e: magnus::Error| {
                                            AssassinateError::ConversionError(format!(
                                                "Failed to convert badchars: {}",
                                                e
                                            ))
                                        })?;
                                    return Ok(unsafe { rstring.as_slice() }.to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fall back to module's payload_badchars method
        if let Ok(badchars_val) = call_method(self.ruby_module, "payload_badchars", &[]) {
            if !badchars_val.is_nil() {
                let rstring: magnus::RString = TryConvert::try_convert(badchars_val)
                    .map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!("Failed to convert badchars: {}", e))
                    })?;
                return Ok(unsafe { rstring.as_slice() }.to_vec());
            }
        }

        Ok(Vec::new())
    }

    /// Get the platform of the current exploit target
    ///
    /// Returns the platform string (e.g., "linux", "windows") for the
    /// currently selected target.
    pub fn target_platform(&self) -> Result<Option<String>> {
        let target = self.current_target_obj()?;
        if target.is_nil() {
            return Ok(None);
        }

        // Get target.platform
        if let Ok(platform_val) = call_method(target, "platform", &[]) {
            if !platform_val.is_nil() {
                // Platform is a PlatformList - get first name
                if let Ok(names_val) = call_method(platform_val, "names", &[]) {
                    if let Some(names_array) = RArray::from_value(names_val) {
                        if names_array.len() > 0 {
                            let name_val: Value = names_array.entry(0).map_err(|e| {
                                AssassinateError::ConversionError(format!(
                                    "Failed to get platform name: {}",
                                    e
                                ))
                            })?;
                            return Ok(Some(value_to_string(name_val)?));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get the architecture of the current exploit target
    ///
    /// Returns the architecture string (e.g., "x86", "x64", "aarch64") for the
    /// currently selected target.
    pub fn target_arch(&self) -> Result<Option<String>> {
        let target = self.current_target_obj()?;
        if target.is_nil() {
            return Ok(None);
        }

        // Get target.arch
        if let Ok(arch_val) = call_method(target, "arch", &[]) {
            if !arch_val.is_nil() {
                // Arch is an array - get first element
                if let Some(arch_array) = RArray::from_value(arch_val) {
                    if arch_array.len() > 0 {
                        let arch_obj: Value = arch_array.entry(0).map_err(|e| {
                            AssassinateError::ConversionError(format!("Failed to get arch: {}", e))
                        })?;
                        return Ok(Some(value_to_string(arch_obj)?));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get the currently selected target index
    pub fn target_index(&self) -> Result<Option<i64>> {
        if !responds_to_public(self.ruby_module, "target") {
            return Ok(None);
        }

        // Get the datastore TARGET value
        if let Ok(Some(target_str)) = self.get_option("TARGET") {
            if let Ok(idx) = target_str.parse::<i64>() {
                return Ok(Some(idx));
            }
        }

        // Fall back to default_target if available
        if let Ok(default_val) = call_method(self.ruby_module, "default_target", &[]) {
            if !default_val.is_nil() {
                let idx: i64 = TryConvert::try_convert(default_val).unwrap_or(0);
                return Ok(Some(idx));
            }
        }

        Ok(Some(0))
    }

    /// Get the current target object (internal helper)
    fn current_target_obj(&self) -> Result<Value> {
        // Check if module responds to targets
        if !responds_to_public(self.ruby_module, "targets") {
            return Ok(crate::ruby_bridge::get_ruby()?.qnil().as_value());
        }

        let targets_val = call_method(self.ruby_module, "targets", &[])?;
        if targets_val.is_nil() {
            return Ok(crate::ruby_bridge::get_ruby()?.qnil().as_value());
        }

        let targets_array = RArray::from_value(targets_val).ok_or_else(|| {
            AssassinateError::ConversionError("targets did not return an array".into())
        })?;

        if targets_array.len() == 0 {
            return Ok(crate::ruby_bridge::get_ruby()?.qnil().as_value());
        }

        // Get target index from datastore or use default
        let target_idx = self.target_index()?.unwrap_or(0) as usize;

        if target_idx < targets_array.len() {
            let target: Value = targets_array.entry(target_idx as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get target: {}", e))
            })?;
            Ok(target)
        } else {
            // Fall back to first target
            let target: Value = targets_array.entry(0).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get target: {}", e))
            })?;
            Ok(target)
        }
    }

    /// Perform a detailed vulnerability check
    ///
    /// Returns a structured CheckCode result with:
    /// - code: The check result code (Safe, Vulnerable, etc.)
    /// - message: Human-readable message
    /// - reason: Why the check returned this result
    /// - details: Additional diagnostic details
    pub fn check_detailed(&self) -> Result<serde_json::Value> {
        let mut opts = Options::new();
        opts.insert("Quiet".into(), RubyVal::Bool(true));
        let opts_val = build_opts(Some(opts))?;

        // Call check_simple on the module
        let result = call_method(self.ruby_module, "check_simple", &[opts_val]);

        match result {
            Ok(check_code) => {
                // CheckCode is a complex object with multiple attributes
                let mut details = serde_json::Map::new();

                // Get the code (symbol like :safe, :vulnerable, etc.)
                let code_str = value_to_string(check_code)?;
                details.insert("code".to_string(), serde_json::json!(code_str));

                // Try to get message
                if let Ok(msg_val) = call_method(check_code, "message", &[]) {
                    if !msg_val.is_nil() {
                        if let Ok(msg) = value_to_string(msg_val) {
                            details.insert("message".to_string(), serde_json::json!(msg));
                        }
                    }
                }

                // Try to get reason (if available)
                if let Ok(reason_val) = call_method(check_code, "reason", &[]) {
                    if !reason_val.is_nil() {
                        if let Ok(reason) = value_to_string(reason_val) {
                            details.insert("reason".to_string(), serde_json::json!(reason));
                        }
                    }
                }

                // Try to get details hash (if available)
                if let Ok(details_val) = call_method(check_code, "details", &[]) {
                    if !details_val.is_nil() {
                        if let Ok(details_json) = crate::ruby_bridge::hash_to_json(details_val) {
                            details.insert("details".to_string(), details_json);
                        }
                    }
                }

                Ok(serde_json::Value::Object(details))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let mut details = serde_json::Map::new();

                if err_msg.contains("NotImplementedError") || err_msg.contains("Unsupported") {
                    details.insert("code".to_string(), serde_json::json!("Unsupported"));
                    details.insert(
                        "message".to_string(),
                        serde_json::json!("Check method not implemented for this module"),
                    );
                } else {
                    details.insert("code".to_string(), serde_json::json!("Unknown"));
                    details.insert("message".to_string(), serde_json::json!(err_msg));
                }

                Ok(serde_json::Value::Object(details))
            }
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Module name='{}' type='{}'>",
            self.fullname()?,
            self.module_type()?
        ))
    }

    // ========== NOP Module Operations ==========

    /// Generate a NOP sled of specified length
    ///
    /// This is only valid for NOP modules (nop/*).
    ///
    /// # Arguments
    /// * `length` - Desired length of the NOP sled in bytes
    /// * `badchars` - Optional bytes to avoid in output
    /// * `save_registers` - Optional list of registers to preserve
    ///
    /// # Returns
    /// NOP sled bytes
    pub fn generate_sled(
        &self,
        length: i32,
        badchars: Option<&[u8]>,
        save_registers: Option<Vec<String>>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_hash: magnus::RHash = ruby.hash_new();

        // Add BadChars if provided
        if let Some(bc) = badchars {
            let key = ruby.str_new("BadChars").as_value();
            let val = ruby.str_from_slice(bc).as_value();
            opts_hash.aset(key, val).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set BadChars: {}", e))
            })?;
        }

        // Add SaveRegisters if provided
        if let Some(regs) = save_registers {
            let key = ruby.str_new("SaveRegisters").as_value();
            let regs_array: magnus::RArray = ruby.ary_new();
            for reg in regs {
                regs_array.push(ruby.str_new(&reg).as_value()).map_err(|e| {
                    AssassinateError::RubyError(format!("Failed to add register: {}", e))
                })?;
            }
            opts_hash.aset(key, regs_array.as_value()).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set SaveRegisters: {}", e))
            })?;
        }

        // Convert length to Ruby integer
        let length_val = ruby.integer_from_i64(length as i64).as_value();

        // Call nop_module.generate_sled(length, opts)
        let sled_val = call_method(self.ruby_module, "generate_sled", &[length_val, opts_hash.as_value()])?;

        // Handle nil result
        if sled_val.is_nil() {
            return Err(AssassinateError::ModuleExecutionError(
                "NOP sled generation returned nil".into(),
            ));
        }

        // Convert Ruby string to bytes
        let sled_str: magnus::RString = TryConvert::try_convert(sled_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!(
                "Failed to convert NOP sled to bytes: {}",
                e
            ))
        })?;

        // Get raw bytes from Ruby string (may contain non-UTF8 data)
        Ok(unsafe { sled_str.as_slice() }.to_vec())
    }
}
