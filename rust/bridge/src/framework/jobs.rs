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

        // First check if job exists - MSF's stop_job silently succeeds for non-existent jobs
        if self.get(job_id)?.is_none() {
            debug!(target: "msf::jobs", "Job {} does not exist, nothing to kill", job_id);
            return Ok(false);
        }

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

    /// Wait for a session from an exploit job using MSF's native session_waiter_event.
    ///
    /// This is the CORRECT way to wait for a session from a background job.
    /// It uses MSF's internal `payload.wait_for_session()` which blocks on the
    /// `session_waiter_event` that is only notified AFTER bootstrap completes.
    ///
    /// # Arguments
    /// * `job_id` - The exploit job ID to wait on
    /// * `timeout_secs` - Timeout in seconds (default: 60)
    ///
    /// # Returns
    /// * `Ok(Some(session_id))` - Session was created
    /// * `Ok(None)` - Timeout waiting for session
    /// * `Err(_)` - Job not found or other error
    pub fn wait_for_session(&self, job_id: &str, timeout_secs: Option<u32>) -> Result<Option<i64>> {
        let timeout = timeout_secs.unwrap_or(60);
        info!(target: "msf::jobs", "Waiting for session from job {} (timeout: {}s)", job_id, timeout);

        let ruby = crate::ruby_bridge::get_ruby()?;
        let id_val = ruby.str_new(job_id).as_value();

        // Get the job object: framework.jobs[job_id]
        let job_val = call_method(*self.ruby_jobs, "[]", &[id_val])?;
        if job_val.is_nil() {
            warn!(target: "msf::jobs", "Job {} not found", job_id);
            return Err(AssassinateError::JobError(format!(
                "Job {} not found",
                job_id
            )));
        }

        // Get the job context: job.ctx which is [exploit, payload]
        let ctx_val = call_method(job_val, "ctx", &[])?;
        if ctx_val.is_nil() {
            warn!(target: "msf::jobs", "Job {} has no context", job_id);
            return Err(AssassinateError::JobError(format!(
                "Job {} has no context",
                job_id
            )));
        }

        // ctx is an Array, get the payload handler (index 1)
        let ctx_array: magnus::RArray = TryConvert::try_convert(ctx_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!(
                "Failed to convert job context to array: {}",
                e
            ))
        })?;

        if ctx_array.len() < 2 {
            warn!(target: "msf::jobs", "Job {} context has insufficient elements", job_id);
            return Err(AssassinateError::JobError(format!(
                "Job {} context has insufficient elements (expected [exploit, payload])",
                job_id
            )));
        }

        // Get the payload handler (ctx[1])
        let payload_val: Value = ctx_array.entry(1).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to get payload from context: {}", e))
        })?;

        debug!(target: "msf::jobs", "Got payload handler from job {}", job_id);

        // Check if payload responds to wait_for_session
        if !crate::ruby_bridge::responds_to_public(payload_val, "wait_for_session") {
            warn!(target: "msf::jobs", "Payload for job {} does not support wait_for_session", job_id);
            return Err(AssassinateError::JobError(format!(
                "Payload does not support wait_for_session"
            )));
        }

        // Call payload.wait_for_session(timeout)
        // This blocks on session_waiter_event which is notified AFTER bootstrap completes.
        // Ruby's Rex::Sync::Event.wait() is GVL-aware - it releases the GVL internally while waiting.
        debug!(target: "msf::jobs", "Calling payload.wait_for_session({}) for job {}", timeout, job_id);
        let timeout_val = ruby.integer_from_i64(timeout as i64).as_value();

        let session_val = call_method(payload_val, "wait_for_session", &[timeout_val])?;

        // Check if we got a session
        if session_val.is_nil() {
            info!(target: "msf::jobs", "Timeout waiting for session from job {}", job_id);
            return Ok(None);
        }

        // Check if it's a session object
        if !crate::ruby_bridge::responds_to_public(session_val, "sid") {
            debug!(target: "msf::jobs", "wait_for_session returned non-session value for job {}", job_id);
            return Ok(None);
        }

        // Get session ID
        let sid_val = call_method(session_val, "sid", &[])?;
        let session_id: i64 = TryConvert::try_convert(sid_val).map_err(|e: magnus::Error| {
            AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
        })?;

        info!(target: "msf::jobs", "Session {} created from job {}", session_id, job_id);
        Ok(Some(session_id))
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
