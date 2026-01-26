//! Job and Plugin management for Metasploit Framework

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, value_to_string, Options};
use log::{debug, info, trace, warn};
use magnus::{value::BoxValue, value::ReprValue, IntoValue, TryConvert, Value};

/// Job manager
///
/// Uses `BoxValue` to protect the Ruby value from garbage collection.
pub struct JobManager {
    pub(crate) ruby_jobs: BoxValue<Value>,
}

impl JobManager {
    /// List all job IDs
    pub fn list(&self) -> Result<Vec<String>> {
        trace!(target: "msf::jobs", "Listing all jobs");
        let keys_val = call_method(*self.ruby_jobs, "keys", &[])?;

        let job_ids: Vec<String> =
            TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert job IDs: {}", e))
            })?;

        debug!(target: "msf::jobs", "Found {} jobs: {:?}", job_ids.len(), job_ids);
        Ok(job_ids)
    }

    /// Get job by ID
    pub fn get(&self, job_id: &str) -> Result<Option<String>> {
        trace!(target: "msf::jobs", "Getting job: {}", job_id);
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        let job_val = call_method(*self.ruby_jobs, "[]", &[id_val])?;

        if job_val.is_nil() {
            debug!(target: "msf::jobs", "Job {} not found", job_id);
            Ok(None)
        } else {
            let job_str = value_to_string(job_val)?;
            debug!(target: "msf::jobs", "Job {} found: {}", job_id, job_str);
            Ok(Some(job_str))
        }
    }

    /// Kill a job by ID
    pub fn kill(&self, job_id: &str) -> Result<bool> {
        info!(target: "msf::jobs", "Killing job: {}", job_id);
        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        // MSF uses stop_job on the job container
        match call_method(*self.ruby_jobs, "stop_job", &[id_val]) {
            Ok(_) => {
                info!(target: "msf::jobs", "Job {} killed", job_id);
                Ok(true)
            }
            Err(e) => {
                warn!(target: "msf::jobs", "Failed to kill job {}: {}", job_id, e);
                Ok(false)
            }
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<JobManager jobs={}>", self.list()?.len()))
    }
}

/// Plugin manager
///
/// Uses `BoxValue` to protect the Ruby value from garbage collection.
pub struct PluginManager {
    pub(crate) ruby_plugins: BoxValue<Value>,
}

impl PluginManager {
    /// List loaded plugins
    pub fn list(&self) -> Result<Vec<String>> {
        trace!(target: "msf::plugins", "Listing loaded plugins");

        // PluginManager is an array of plugin instances
        // Call to_a to convert to array
        let plugins_array: magnus::RArray =
            TryConvert::try_convert(*self.ruby_plugins).map_err(|e: magnus::Error| {
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

        debug!(target: "msf::plugins", "Found {} plugins: {:?}", plugin_names.len(), plugin_names);
        Ok(plugin_names)
    }

    /// Load a plugin from path
    pub fn load(&self, path: &str, options: Option<Options>) -> Result<String> {
        info!(target: "msf::plugins", "Loading plugin from: {}", path);

        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash using RHash::aset
        let opts_hash = ruby.hash_new();

        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                trace!(target: "msf::plugins", "Setting plugin option: {}", key);
                opts_hash.aset(ruby.str_new(&key), value.into_value_with(&ruby)).map_err(|e| {
                    AssassinateError::RubyError(format!("Failed to set option: {}", e))
                })?;
            }
        }

        // Load the plugin
        let path_val = ruby.str_new(path).as_value();
        let plugin_instance = call_method(*self.ruby_plugins, "load", &[path_val, opts_hash.as_value()])?;

        // Get plugin name
        let name_val = call_method(plugin_instance, "name", &[])?;
        let name = value_to_string(name_val)?;

        info!(target: "msf::plugins", "Plugin loaded: {}", name);
        Ok(name)
    }

    /// Unload a plugin by name
    pub fn unload(&self, plugin_name: &str) -> Result<bool> {
        info!(target: "msf::plugins", "Unloading plugin: {}", plugin_name);

        // PluginManager is an array, so we need to find the plugin by name
        let plugins_array: magnus::RArray =
            TryConvert::try_convert(*self.ruby_plugins).map_err(|e: magnus::Error| {
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
                call_method(*self.ruby_plugins, "unload", &[plugin_val])?;
                info!(target: "msf::plugins", "Plugin unloaded: {}", plugin_name);
                return Ok(true);
            }
        }

        // Plugin not found
        warn!(target: "msf::plugins", "Plugin not found: {}", plugin_name);
        Ok(false)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<PluginManager plugins={}>", self.list()?.len()))
    }
}
