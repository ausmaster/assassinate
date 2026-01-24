//! Framework types and operations for Metasploit Framework interaction
//!
//! This module provides the core types for interacting with Metasploit Framework:
//! - [`Framework`] - Main entry point for MSF operations
//! - [`Module`] - Individual MSF modules (exploits, auxiliary, post, etc.)
//! - [`Session`] / [`SessionManager`] - Session management with FS/Process operations
//! - [`DbManager`] - Database operations
//! - [`JobManager`] / [`PluginManager`] - Jobs and plugins
//! - [`PayloadGenerator`] - Payload generation
//! - [`DataStore`] - Key-value configuration store
//! - [`RouteManager`] / [`Route`] - Network routing through sessions (pivoting)

mod db;
mod jobs;
mod module;
mod payload;
mod routing;
mod session;

// Re-export all public types
pub use db::DbManager;
pub use jobs::{JobManager, PluginManager};
pub use module::Module;
pub use payload::PayloadGenerator;
pub use routing::{Route, RouteManager};
pub use session::{Session, SessionManager};

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, create_framework, value_to_string};
use magnus::{value::ReprValue, TryConvert, Value};
use std::collections::HashMap;

/// Core Metasploit Framework interface
///
/// This type provides access to the Metasploit Framework functionality through Ruby FFI.
/// Python bindings use a thread-local singleton pattern instead of exposing Framework directly.
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

    /// Create a Framework wrapper from an existing Ruby framework object
    /// Useful for tests and when you already have a framework Value
    pub fn from_raw(ruby_framework: Value) -> Self {
        Framework { ruby_framework }
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
        if module_instance.is_nil() {
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
        Ok(threads_val.to_bool())
    }

    // ========== Framework Management Operations ==========

    /// Hot reload all framework modules
    ///
    /// Returns module counts by type after reloading
    pub fn reload_modules(&self) -> Result<HashMap<String, i64>> {
        let modules_manager = call_method(self.ruby_framework, "modules", &[])?;

        // Call reload_modules which returns a hash of counts by type
        let result_val = call_method(modules_manager, "reload_modules", &[])?;

        // Convert Ruby hash to JSON then to HashMap
        let json = crate::ruby_bridge::hash_to_json(result_val)?;
        let stats: HashMap<String, i64> = serde_json::from_value(json)
            .map_err(|e| AssassinateError::ConversionError(format!("Failed to convert reload stats: {}", e)))?;

        Ok(stats)
    }

    /// Save framework configuration to disk
    pub fn save(&self) -> Result<()> {
        call_method(self.ruby_framework, "save_config", &[])?;
        Ok(())
    }

    /// Add a new module path to the framework
    ///
    /// The path must be accessible and contain top-level directories for module types
    /// (exploits, auxiliary, post, encoders, nops, payloads, evasion)
    pub fn add_module_path(&self, path: &str) -> Result<HashMap<String, i64>> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let modules_manager = call_method(self.ruby_framework, "modules", &[])?;

        let path_val = ruby.str_new(path).as_value();

        // add_module_path returns a hash of counts by type
        let result_val = call_method(modules_manager, "add_module_path", &[path_val])?;

        // Convert Ruby hash to JSON then to HashMap
        let json = crate::ruby_bridge::hash_to_json(result_val)?;
        let stats: HashMap<String, i64> = serde_json::from_value(json)
            .map_err(|e| AssassinateError::ConversionError(format!("Failed to convert module path stats: {}", e)))?;

        Ok(stats)
    }

    /// Get module statistics (counts by type)
    pub fn module_stats(&self) -> Result<HashMap<String, i64>> {
        let stats_val = call_method(self.ruby_framework, "stats", &[])?;

        let mut stats = HashMap::new();

        // Extract each stat count
        let exploits_val = call_method(stats_val, "num_exploits", &[])?;
        let auxiliary_val = call_method(stats_val, "num_auxiliary", &[])?;
        let post_val = call_method(stats_val, "num_post", &[])?;
        let encoders_val = call_method(stats_val, "num_encoders", &[])?;
        let nops_val = call_method(stats_val, "num_nops", &[])?;
        let payloads_val = call_method(stats_val, "num_payloads", &[])?;
        let evasions_val = call_method(stats_val, "num_evasion", &[])?;

        stats.insert("exploits".to_string(), TryConvert::try_convert(exploits_val).unwrap_or(0));
        stats.insert("auxiliary".to_string(), TryConvert::try_convert(auxiliary_val).unwrap_or(0));
        stats.insert("post".to_string(), TryConvert::try_convert(post_val).unwrap_or(0));
        stats.insert("encoders".to_string(), TryConvert::try_convert(encoders_val).unwrap_or(0));
        stats.insert("nops".to_string(), TryConvert::try_convert(nops_val).unwrap_or(0));
        stats.insert("payloads".to_string(), TryConvert::try_convert(payloads_val).unwrap_or(0));
        stats.insert("evasions".to_string(), TryConvert::try_convert(evasions_val).unwrap_or(0));

        Ok(stats)
    }

    // ========== Routing Operations ==========

    /// Get the route manager for adding/removing routes
    pub fn routes(&self) -> Result<RouteManager> {
        let sessions_val = call_method(self.ruby_framework, "sessions", &[])?;
        RouteManager::new(sessions_val)
    }

    /// Add a route through a session (convenience method)
    ///
    /// # Arguments
    /// * `subnet` - The subnet to route (e.g., "10.10.10.0")
    /// * `netmask` - The netmask (e.g., "255.255.255.0" or "24" for CIDR)
    /// * `session_id` - The session ID to route through
    ///
    /// # Returns
    /// `true` if the route was added, `false` if it already exists
    pub fn route_add(&self, subnet: &str, netmask: &str, session_id: i64) -> Result<bool> {
        self.routes()?.add_route(subnet, netmask, session_id)
    }

    /// Remove a route through a session (convenience method)
    ///
    /// # Arguments
    /// * `subnet` - The subnet to remove (e.g., "10.10.10.0")
    /// * `netmask` - The netmask (e.g., "255.255.255.0" or "24" for CIDR)
    /// * `session_id` - The session ID the route goes through
    ///
    /// # Returns
    /// `true` if the route was removed, `false` if it wasn't found
    pub fn route_remove(&self, subnet: &str, netmask: &str, session_id: i64) -> Result<bool> {
        self.routes()?.remove_route(subnet, netmask, session_id)
    }

    /// List all routes (convenience method)
    pub fn route_list(&self) -> Result<Vec<Route>> {
        self.routes()?.list_routes()
    }

    /// Flush all routes (convenience method)
    pub fn route_flush(&self) -> Result<()> {
        self.routes()?.flush_routes()
    }

    /// Check if a route exists (convenience method)
    pub fn route_exists(&self, subnet: &str, netmask: &str) -> Result<bool> {
        self.routes()?.route_exists(subnet, netmask)
    }

    /// Find the best session for routing to an address (convenience method)
    pub fn route_get(&self, addr: &str) -> Result<Option<i64>> {
        self.routes()?.best_comm(addr)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<Framework version={}>", self.version()?))
    }
}

// Note: Pyo3 bindings are in src/pyo3/pymodule.rs
// Framework is not directly exposed as a pyclass - instead, module-level
// functions use a thread-local singleton pattern for Python API.

/// DataStore for framework and module configuration
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
        if result.is_nil() {
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
