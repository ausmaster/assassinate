//! Job and Plugin management for Metasploit Framework

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, value_to_string};
use magnus::{value::ReprValue, TryConvert, Value};
use std::collections::HashMap;

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

        if job_val.is_nil() {
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

    /// Load a plugin from path
    pub fn load(&self, path: &str, options: Option<HashMap<String, String>>) -> Result<String> {
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
    pub fn unload(&self, plugin_name: &str) -> Result<bool> {
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
