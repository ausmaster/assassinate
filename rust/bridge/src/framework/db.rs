//! Database manager for Metasploit's database operations

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, get_string_attr, sym, value_to_string, Options};
use log::{debug, error, info, trace, warn};
use magnus::{value::BoxValue, value::ReprValue, IntoValue, RArray, RHash, TryConvert, Value};

/// Database manager
///
/// Uses `BoxValue` to protect the Ruby value from garbage collection.
pub struct DbManager {
    pub(crate) ruby_db: BoxValue<Value>,
}

impl DbManager {
    /// Get all hosts
    pub fn hosts(&self) -> Result<Vec<String>> {
        debug!(target: "msf::db", "Getting all hosts from database");

        // MSF hosts() returns an ActiveRecord relation of Mdm::Host objects
        // We need to convert each host to a string representation (IP address)
        let hosts_val = call_method(*self.ruby_db, "hosts", &[])?;

        // Check if nil (database might be empty or not configured)
        if hosts_val.is_nil() {
            trace!(target: "msf::db", "Hosts query returned nil");
            return Ok(Vec::new());
        }

        // Convert to array by calling to_a on the relation
        let hosts_array_val = call_method(hosts_val, "to_a", &[])?;

        // Use RArray for efficient iteration
        let hosts_array = RArray::from_value(hosts_array_val).ok_or_else(|| {
            AssassinateError::ConversionError("hosts.to_a did not return an array".to_string())
        })?;

        let mut result = Vec::with_capacity(hosts_array.len());
        for i in 0..hosts_array.len() {
            let host_obj: Value = hosts_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get host at {}: {}", i, e))
            })?;
            // Get the address attribute from the Mdm::Host object
            let addr = call_method(host_obj, "address", &[])?;
            if let Ok(addr_str) = value_to_string(addr) {
                result.push(addr_str);
            }
        }

        debug!(target: "msf::db", "Found {} hosts in database", result.len());
        Ok(result)
    }

    /// Get all services
    pub fn services(&self) -> Result<Vec<String>> {
        debug!(target: "msf::db", "Getting all services from database");

        let services_val = call_method(*self.ruby_db, "services", &[])?;

        // Check if nil (database might be empty or not configured)
        if services_val.is_nil() {
            trace!(target: "msf::db", "Services query returned nil");
            return Ok(Vec::new());
        }

        // Convert to array - MSF returns Mdm::Service objects
        let services_array_val = call_method(services_val, "to_a", &[])?;

        // Use RArray for efficient iteration
        let services_array = RArray::from_value(services_array_val).ok_or_else(|| {
            AssassinateError::ConversionError("services.to_a did not return an array".to_string())
        })?;

        let mut result = Vec::with_capacity(services_array.len());
        for i in 0..services_array.len() {
            let service_obj: Value = services_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get service at {}: {}", i, e))
            })?;
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

        debug!(target: "msf::db", "Found {} services in database", result.len());
        Ok(result)
    }

    /// Report a host to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with host parameters (e.g., "host", "os_name", "os_flavor")
    ///
    /// # Returns
    /// Returns the host ID from the database
    pub fn report_host(&self, opts: Option<Options>) -> Result<i64> {
        info!(target: "msf::db", "Reporting host to database");
        trace!(target: "msf::db", "report_host options: {:?}", opts.as_ref().map(|o| o.keys().collect::<Vec<_>>()));
        self.report_to_db("report_host", opts)
    }

    /// Report a service to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with service parameters (e.g., "host", "port", "proto", "name")
    ///
    /// # Returns
    /// Returns the service ID from the database
    pub fn report_service(&self, opts: Option<Options>) -> Result<i64> {
        self.report_to_db("report_service", opts)
    }

    /// Report a vulnerability to the database
    ///
    /// # Arguments
    /// * `opts` - Optional HashMap with vulnerability parameters (e.g., "host", "name", "info")
    ///
    /// # Returns
    /// Returns the vulnerability ID from the database
    pub fn report_vuln(&self, opts: Option<Options>) -> Result<i64> {
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
    pub fn report_cred(&self, opts: Option<Options>) -> Result<i64> {
        self.report_to_db("report_cred", opts)
    }

    /// Get all vulnerabilities
    pub fn vulns(&self) -> Result<Vec<String>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // MSF vulns() expects a workspace parameter, use empty hash for default workspace
        let opts_val = ruby.hash_new().as_value();

        let vulns_val = call_method(*self.ruby_db, "vulns", &[opts_val])?;

        // Check if nil (database might be empty or not configured)
        if vulns_val.is_nil() {
            return Ok(Vec::new());
        }

        // Convert to array - MSF returns Mdm::Vuln objects
        let vulns_array_val = call_method(vulns_val, "to_a", &[])?;

        // Use RArray for efficient iteration
        let vulns_array = RArray::from_value(vulns_array_val).ok_or_else(|| {
            AssassinateError::ConversionError("vulns.to_a did not return an array".to_string())
        })?;

        let mut result = Vec::with_capacity(vulns_array.len());
        for i in 0..vulns_array.len() {
            let vuln_obj: Value = vulns_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get vuln at {}: {}", i, e))
            })?;
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
        let creds_val = call_method(*self.ruby_db, "creds", &[])?;

        // Check if nil (database might be empty or not configured)
        if creds_val.is_nil() {
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
        let loot_val = call_method(*self.ruby_db, "loot", &[])?;

        // Check if nil (database might be empty or not configured)
        if loot_val.is_nil() {
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
        opts: Option<Options>,
    ) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys (MSF expects symbol keys like :host, not string keys)
        let opts_val = ruby.hash_new().as_value();

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                // Convert string key to symbol
                let key_sym = ruby.to_symbol(&key);
                let value_val = value.into_value_with(&ruby);
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
                *self.ruby_db,
                "find_workspace",
                &[ruby.str_new(&workspace_name).as_value()],
            )?;

            // If workspace doesn't exist, create it
            if workspace_obj.is_nil() {
                let add_opts = ruby.hash_new().as_value();
                let name_sym = ruby.to_symbol("name");
                call_method(
                    add_opts,
                    "[]=",
                    &[
                        name_sym.as_value(),
                        ruby.str_new(&workspace_name).as_value(),
                    ],
                )?;
                workspace_obj = call_method(*self.ruby_db, "add_workspace", &[add_opts])?;
            }

            // Inject workspace object into options hash
            let workspace_sym = ruby.to_symbol("workspace");
            call_method(opts_val, "[]=", &[workspace_sym.as_value(), workspace_obj])?;
        }

        let result_val = call_method(*self.ruby_db, method_name, &[opts_val])?;

        // MSF report_* methods return ActiveRecord objects (Mdm::Host, Mdm::Service, etc.)
        // We need to extract the ID from the object
        if result_val.is_nil() {
            return Ok(0);
        }

        // Try to get .id from the returned object
        let id_val = call_method(result_val, "id", &[])?;
        let id: i64 = TryConvert::try_convert(id_val).unwrap_or(0);
        Ok(id)
    }

    // ========== Workspace Management ==========

    /// List all workspaces
    pub fn workspaces(&self) -> Result<Vec<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create empty opts hash
        let opts_val = ruby.hash_new().as_value();

        let workspaces_val = call_method(*self.ruby_db, "workspaces", &[opts_val])?;

        // Check if nil
        if workspaces_val.is_nil() {
            return Ok(Vec::new());
        }

        // Convert to array
        let workspaces_array_val = call_method(workspaces_val, "to_a", &[])?;

        // Use RArray for efficient iteration
        let workspaces_array = RArray::from_value(workspaces_array_val).ok_or_else(|| {
            AssassinateError::ConversionError("workspaces.to_a did not return an array".to_string())
        })?;

        let mut result = Vec::with_capacity(workspaces_array.len());
        for i in 0..workspaces_array.len() {
            let workspace_obj: Value = workspaces_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get workspace at {}: {}", i, e))
            })?;

            // Extract workspace attributes
            let mut ws_map = serde_json::Map::new();

            // Get ID
            if let Ok(id_val) = call_method(workspace_obj, "id", &[]) {
                if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                    ws_map.insert("id".to_string(), serde_json::json!(id));
                }
            }

            // Get name
            if let Ok(name_val) = call_method(workspace_obj, "name", &[]) {
                if let Ok(name) = value_to_string(name_val) {
                    ws_map.insert("name".to_string(), serde_json::json!(name));
                }
            }

            // Get created_at
            if let Ok(created_val) = call_method(workspace_obj, "created_at", &[]) {
                if let Ok(created_str) =
                    value_to_string(call_method(created_val, "to_s", &[])?)
                {
                    ws_map.insert("created_at".to_string(), serde_json::json!(created_str));
                }
            }

            result.push(serde_json::Value::Object(ws_map));
        }

        Ok(result)
    }

    /// Get current workspace
    pub fn workspace(&self) -> Result<serde_json::Value> {
        let workspace_obj = call_method(*self.ruby_db, "workspace", &[])?;

        if workspace_obj.is_nil() {
            return Ok(serde_json::json!(null));
        }

        // Extract workspace attributes
        let mut ws_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(workspace_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                ws_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(name_val) = call_method(workspace_obj, "name", &[]) {
            if let Ok(name) = value_to_string(name_val) {
                ws_map.insert("name".to_string(), serde_json::json!(name));
            }
        }

        Ok(serde_json::Value::Object(ws_map))
    }

    /// Set current workspace by name
    pub fn set_workspace(&self, name: &str) -> Result<()> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Find the workspace first
        let workspace_obj = call_method(
            *self.ruby_db,
            "find_workspace",
            &[ruby.str_new(name).as_value()],
        )?;

        if workspace_obj.is_nil() {
            return Err(AssassinateError::NotFound(format!(
                "Workspace '{}' not found",
                name
            )));
        }

        // Set it as current workspace
        call_method(*self.ruby_db, "workspace=", &[workspace_obj])?;

        Ok(())
    }

    /// Create a new workspace
    pub fn add_workspace(&self, name: &str) -> Result<serde_json::Value> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // WorkspaceDataProxy.add_workspace takes a STRING (workspace name), not a hash.
        // The proxy internally converts it to { name: workspace_name } before calling
        // the underlying data service. This matches find_workspace's signature.
        let workspace_obj = call_method(
            *self.ruby_db,
            "add_workspace",
            &[ruby.str_new(name).as_value()],
        )?;

        // Check if nil
        if workspace_obj.is_nil() {
            return Err(AssassinateError::RubyError(
                "add_workspace returned nil - workspace creation failed".to_string(),
            ));
        }

        // Extract workspace info
        let mut ws_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(workspace_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                ws_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(name_val) = call_method(workspace_obj, "name", &[]) {
            if let Ok(name_str) = value_to_string(name_val) {
                ws_map.insert("name".to_string(), serde_json::json!(name_str));
            }
        }

        Ok(serde_json::Value::Object(ws_map))
    }

    /// Find workspace by name
    pub fn find_workspace(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        let workspace_obj = call_method(
            *self.ruby_db,
            "find_workspace",
            &[ruby.str_new(name).as_value()],
        )?;

        if workspace_obj.is_nil() {
            return Ok(None);
        }

        // Extract workspace info
        let mut ws_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(workspace_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                ws_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(name_val) = call_method(workspace_obj, "name", &[]) {
            if let Ok(name_str) = value_to_string(name_val) {
                ws_map.insert("name".to_string(), serde_json::json!(name_str));
            }
        }

        Ok(Some(serde_json::Value::Object(ws_map)))
    }

    /// Delete workspace by ID
    pub fn delete_workspace(&self, workspace_id: i64) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with :ids array using RHash::aset and LazyId
        let opts_hash = ruby.hash_new();

        // Create array with single ID using RArray::push
        let ids_array = ruby.ary_new();
        ids_array.push(ruby.integer_from_i64(workspace_id)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to push ID to array: {}", e))
        })?;

        opts_hash.aset(*sym::IDS, ids_array).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set ids: {}", e))
        })?;

        // Call delete_workspaces
        match call_method(*self.ruby_db, "delete_workspaces", &[opts_hash.as_value()]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // ========== Note Management ==========

    /// List all notes in current workspace
    pub fn notes(&self, opts: Option<Options>) -> Result<Vec<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash using RHash::aset
        let opts_hash = ruby.hash_new();

        if let Some(opts_map) = opts {
            for (key, value) in opts_map {
                let key_sym = ruby.to_symbol(&key);
                opts_hash.aset(key_sym, value.into_value_with(&ruby)).map_err(|e| {
                    AssassinateError::RubyError(format!("Failed to set option: {}", e))
                })?;
            }
        }

        let notes_val = call_method(*self.ruby_db, "notes", &[opts_hash.as_value()])?;

        if notes_val.is_nil() {
            return Ok(Vec::new());
        }

        // Convert to array
        let notes_array_val = call_method(notes_val, "to_a", &[])?;

        // Use RArray for efficient iteration
        let notes_array = RArray::from_value(notes_array_val).ok_or_else(|| {
            AssassinateError::ConversionError("notes.to_a did not return an array".to_string())
        })?;

        let mut result = Vec::with_capacity(notes_array.len());
        for i in 0..notes_array.len() {
            let note_obj: Value = notes_array.entry(i as isize).map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to get note at {}: {}", i, e))
            })?;

            let mut note_map = serde_json::Map::new();

            // Get ID
            if let Ok(id_val) = call_method(note_obj, "id", &[]) {
                if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                    note_map.insert("id".to_string(), serde_json::json!(id));
                }
            }

            // Get note type
            if let Ok(ntype_val) = call_method(note_obj, "ntype", &[]) {
                if let Ok(ntype) = value_to_string(ntype_val) {
                    note_map.insert("ntype".to_string(), serde_json::json!(ntype));
                }
            }

            // Get data (serialized)
            if let Ok(data_val) = call_method(note_obj, "data", &[]) {
                if !data_val.is_nil() {
                    // Try to convert to JSON
                    if let Ok(data_json) = crate::ruby_bridge::hash_to_json(data_val) {
                        note_map.insert("data".to_string(), data_json);
                    }
                }
            }

            // Get host if present
            if let Ok(host_val) = call_method(note_obj, "host", &[]) {
                if !host_val.is_nil() {
                    if let Ok(addr_val) = call_method(host_val, "address", &[]) {
                        if let Ok(addr) = value_to_string(addr_val) {
                            note_map.insert("host".to_string(), serde_json::json!(addr));
                        }
                    }
                }
            }

            // Get created_at
            if let Ok(created_val) = call_method(note_obj, "created_at", &[]) {
                if let Ok(created_str) =
                    value_to_string(call_method(created_val, "to_s", &[])?)
                {
                    note_map.insert("created_at".to_string(), serde_json::json!(created_str));
                }
            }

            result.push(serde_json::Value::Object(note_map));
        }

        Ok(result)
    }

    /// Report a note to the database
    pub fn report_note(&self, opts: Options) -> Result<i64> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys using RHash::aset
        let opts_hash = ruby.hash_new();

        for (key, value) in opts {
            let key_sym = ruby.to_symbol(&key);
            opts_hash.aset(key_sym, value.into_value_with(&ruby)).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }

        let result_val = call_method(*self.ruby_db, "report_note", &[opts_hash.as_value()])?;

        // Check if the result is nil
        if result_val.is_nil() {
            return Err(AssassinateError::RubyError(
                "report_note returned nil - note creation failed (database may not be active or workspace not set)".to_string(),
            ));
        }

        // report_note might return the note object directly or a hash with :note key
        // Try to get ID directly first
        let note_obj = if let Ok(id_test) = call_method(result_val, "id", &[]) {
            if !id_test.is_nil() {
                // result_val is the note object directly
                result_val
            } else {
                // Try hash with :note key using RHash::aref with LazyId
                if let Some(result_hash) = RHash::from_value(result_val) {
                    result_hash.aref(*sym::NOTE).map_err(|e| {
                        AssassinateError::RubyError(format!("Failed to get note: {}", e))
                    })?
                } else {
                    return Err(AssassinateError::RubyError(
                        "Result is not a hash".to_string(),
                    ));
                }
            }
        } else {
            // Try hash with :note key using RHash::aref with LazyId
            if let Some(result_hash) = RHash::from_value(result_val) {
                result_hash.aref(*sym::NOTE).map_err(|e| {
                    AssassinateError::RubyError(format!("Failed to get note: {}", e))
                })?
            } else {
                return Err(AssassinateError::RubyError(
                    "Result is not a hash".to_string(),
                ));
            }
        };

        // Check if note object is nil
        if note_obj.is_nil() {
            return Err(AssassinateError::RubyError(
                "Note object is nil - failed to create or retrieve note".to_string(),
            ));
        }

        // Get the note ID
        let id_val = call_method(note_obj, "id", &[])?;
        let id: i64 = TryConvert::try_convert(id_val).unwrap_or(0);

        Ok(id)
    }

    /// Delete notes by IDs
    pub fn delete_note(&self, note_ids: Vec<i64>) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with :ids array using RHash::aset and LazyId
        let opts_hash = ruby.hash_new();

        // Create array of IDs using RArray::push
        let ids_array = ruby.ary_new();
        for id in note_ids {
            ids_array.push(ruby.integer_from_i64(id)).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to push ID to array: {}", e))
            })?;
        }

        opts_hash.aset(*sym::IDS, ids_array).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set ids: {}", e))
        })?;

        // Call delete_note
        let deleted_val = call_method(*self.ruby_db, "delete_note", &[opts_hash.as_value()])?;

        // Returns array of deleted notes - use RArray::len() for efficient length
        if let Some(deleted_array) = RArray::from_value(deleted_val) {
            Ok(deleted_array.len())
        } else {
            Ok(0)
        }
    }

    // ========== Individual Record Queries (4.5B) ==========

    /// Get a single host by address
    ///
    /// # Arguments
    /// * `address` - IP address of the host to find
    ///
    /// # Returns
    /// Host info as JSON or None if not found
    pub fn get_host(&self, address: &str) -> Result<Option<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with :address key
        let opts_hash = ruby.hash_new();
        let addr_sym = ruby.to_symbol("address");
        opts_hash.aset(addr_sym, ruby.str_new(address)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set address: {}", e))
        })?;

        // MSF's get_host requires :workspace parameter
        // Inject the current workspace object
        let workspace_obj = call_method(*self.ruby_db, "workspace", &[])?;
        if !workspace_obj.is_nil() {
            let workspace_sym = ruby.to_symbol("workspace");
            opts_hash.aset(workspace_sym, workspace_obj).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set workspace: {}", e))
            })?;
        }

        let host_obj = call_method(*self.ruby_db, "get_host", &[opts_hash.as_value()])?;

        if host_obj.is_nil() {
            return Ok(None);
        }

        // Extract host attributes
        let mut host_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(host_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                host_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(addr_val) = call_method(host_obj, "address", &[]) {
            if let Ok(addr) = value_to_string(addr_val) {
                host_map.insert("address".to_string(), serde_json::json!(addr));
            }
        }

        if let Ok(os_name_val) = call_method(host_obj, "os_name", &[]) {
            if !os_name_val.is_nil() {
                if let Ok(os_name) = value_to_string(os_name_val) {
                    host_map.insert("os_name".to_string(), serde_json::json!(os_name));
                }
            }
        }

        if let Ok(os_flavor_val) = call_method(host_obj, "os_flavor", &[]) {
            if !os_flavor_val.is_nil() {
                if let Ok(os_flavor) = value_to_string(os_flavor_val) {
                    host_map.insert("os_flavor".to_string(), serde_json::json!(os_flavor));
                }
            }
        }

        if let Ok(name_val) = call_method(host_obj, "name", &[]) {
            if !name_val.is_nil() {
                if let Ok(name) = value_to_string(name_val) {
                    host_map.insert("name".to_string(), serde_json::json!(name));
                }
            }
        }

        if let Ok(state_val) = call_method(host_obj, "state", &[]) {
            if !state_val.is_nil() {
                if let Ok(state) = value_to_string(state_val) {
                    host_map.insert("state".to_string(), serde_json::json!(state));
                }
            }
        }

        Ok(Some(serde_json::Value::Object(host_map)))
    }

    /// Get a single service by host and port
    ///
    /// # Arguments
    /// * `host` - IP address of the host
    /// * `port` - Port number
    /// * `proto` - Protocol (default: "tcp")
    ///
    /// # Returns
    /// Service info as JSON or None if not found
    pub fn get_service(&self, host: &str, port: i32, proto: Option<&str>) -> Result<Option<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_hash = ruby.hash_new();

        let host_sym = ruby.to_symbol("host");
        let port_sym = ruby.to_symbol("port");
        let proto_sym = ruby.to_symbol("proto");

        opts_hash.aset(host_sym, ruby.str_new(host)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set host: {}", e))
        })?;

        opts_hash.aset(port_sym, ruby.integer_from_i64(port as i64)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set port: {}", e))
        })?;

        let protocol = proto.unwrap_or("tcp");
        opts_hash.aset(proto_sym, ruby.str_new(protocol)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set proto: {}", e))
        })?;

        // MSF's get_service requires :workspace parameter
        let workspace_obj = call_method(*self.ruby_db, "workspace", &[])?;
        if !workspace_obj.is_nil() {
            let workspace_sym = ruby.to_symbol("workspace");
            opts_hash.aset(workspace_sym, workspace_obj).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set workspace: {}", e))
            })?;
        }

        let service_obj = call_method(*self.ruby_db, "get_service", &[opts_hash.as_value()])?;

        if service_obj.is_nil() {
            return Ok(None);
        }

        // Extract service attributes
        let mut svc_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(service_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                svc_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(port_val) = call_method(service_obj, "port", &[]) {
            if let Ok(port) = crate::ruby_bridge::value_to_i64(port_val) {
                svc_map.insert("port".to_string(), serde_json::json!(port));
            }
        }

        if let Ok(proto_val) = call_method(service_obj, "proto", &[]) {
            if let Ok(proto_str) = value_to_string(proto_val) {
                svc_map.insert("proto".to_string(), serde_json::json!(proto_str));
            }
        }

        if let Ok(name_val) = call_method(service_obj, "name", &[]) {
            if !name_val.is_nil() {
                if let Ok(name) = value_to_string(name_val) {
                    svc_map.insert("name".to_string(), serde_json::json!(name));
                }
            }
        }

        if let Ok(state_val) = call_method(service_obj, "state", &[]) {
            if !state_val.is_nil() {
                if let Ok(state) = value_to_string(state_val) {
                    svc_map.insert("state".to_string(), serde_json::json!(state));
                }
            }
        }

        if let Ok(info_val) = call_method(service_obj, "info", &[]) {
            if !info_val.is_nil() {
                if let Ok(info) = value_to_string(info_val) {
                    svc_map.insert("info".to_string(), serde_json::json!(info));
                }
            }
        }

        // Get host address
        if let Ok(host_obj) = call_method(service_obj, "host", &[]) {
            if !host_obj.is_nil() {
                if let Ok(addr_val) = call_method(host_obj, "address", &[]) {
                    if let Ok(addr) = value_to_string(addr_val) {
                        svc_map.insert("host".to_string(), serde_json::json!(addr));
                    }
                }
            }
        }

        Ok(Some(serde_json::Value::Object(svc_map)))
    }

    /// Get a single vulnerability by opts
    ///
    /// # Arguments
    /// * `opts` - Query options (host, name, etc.)
    ///
    /// # Returns
    /// Vulnerability info as JSON or None if not found
    pub fn get_vuln(&self, opts: Options) -> Result<Option<serde_json::Value>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys
        let opts_hash = ruby.hash_new();

        for (key, value) in opts {
            let key_sym = ruby.to_symbol(&key);
            opts_hash.aset(key_sym, value.into_value_with(&ruby)).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }

        // MSF's get_vuln requires :workspace parameter
        let workspace_obj = call_method(*self.ruby_db, "workspace", &[])?;
        if !workspace_obj.is_nil() {
            let workspace_sym = ruby.to_symbol("workspace");
            opts_hash.aset(workspace_sym, workspace_obj).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set workspace: {}", e))
            })?;
        }

        let vuln_obj = call_method(*self.ruby_db, "get_vuln", &[opts_hash.as_value()])?;

        if vuln_obj.is_nil() {
            return Ok(None);
        }

        // Extract vuln attributes
        let mut vuln_map = serde_json::Map::new();

        if let Ok(id_val) = call_method(vuln_obj, "id", &[]) {
            if let Ok(id) = crate::ruby_bridge::value_to_i64(id_val) {
                vuln_map.insert("id".to_string(), serde_json::json!(id));
            }
        }

        if let Ok(name_val) = call_method(vuln_obj, "name", &[]) {
            if let Ok(name) = value_to_string(name_val) {
                vuln_map.insert("name".to_string(), serde_json::json!(name));
            }
        }

        if let Ok(info_val) = call_method(vuln_obj, "info", &[]) {
            if !info_val.is_nil() {
                if let Ok(info) = value_to_string(info_val) {
                    vuln_map.insert("info".to_string(), serde_json::json!(info));
                }
            }
        }

        // Get refs if present
        if let Ok(refs_val) = call_method(vuln_obj, "refs", &[]) {
            if !refs_val.is_nil() {
                let refs_array = call_method(refs_val, "to_a", &[])?;
                if let Some(refs) = RArray::from_value(refs_array) {
                    let mut ref_list = Vec::new();
                    for i in 0..refs.len() {
                        if let Ok(ref_obj) = refs.entry::<Value>(i as isize) {
                            if let Ok(name_val) = call_method(ref_obj, "name", &[]) {
                                if let Ok(name) = value_to_string(name_val) {
                                    ref_list.push(serde_json::json!(name));
                                }
                            }
                        }
                    }
                    if !ref_list.is_empty() {
                        vuln_map.insert("refs".to_string(), serde_json::json!(ref_list));
                    }
                }
            }
        }

        Ok(Some(serde_json::Value::Object(vuln_map)))
    }

    /// Update a host by ID
    ///
    /// # Arguments
    /// * `id` - Host ID
    /// * `opts` - Fields to update (os_name, os_flavor, name, state, etc.)
    ///
    /// # Returns
    /// true if update succeeded
    pub fn update_host(&self, id: i64, opts: Options) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys
        let opts_hash = ruby.hash_new();

        // Add the ID
        let id_sym = ruby.to_symbol("id");
        opts_hash.aset(id_sym, ruby.integer_from_i64(id)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set id: {}", e))
        })?;

        // Add other options
        for (key, value) in opts {
            let key_sym = ruby.to_symbol(&key);
            opts_hash.aset(key_sym, value.into_value_with(&ruby)).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }

        // Call update_host
        let result = call_method(*self.ruby_db, "update_host", &[opts_hash.as_value()])?;

        // Returns the updated host object or nil
        Ok(!result.is_nil())
    }

    /// Delete a host by ID
    ///
    /// # Arguments
    /// * `id` - Host ID to delete
    ///
    /// # Returns
    /// true if delete succeeded
    pub fn delete_host(&self, id: i64) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with :ids array
        let opts_hash = ruby.hash_new();

        let ids_array = ruby.ary_new();
        ids_array.push(ruby.integer_from_i64(id)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to push ID to array: {}", e))
        })?;

        opts_hash.aset(*sym::IDS, ids_array).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set ids: {}", e))
        })?;

        // Call delete_host (or delete_hosts depending on MSF version)
        match call_method(*self.ruby_db, "delete_host", &[opts_hash.as_value()]) {
            Ok(_) => Ok(true),
            Err(_) => {
                // Try plural form
                match call_method(*self.ruby_db, "delete_hosts", &[opts_hash.as_value()]) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Update a service
    ///
    /// # Arguments
    /// * `id` - Service ID
    /// * `opts` - Fields to update (name, state, info, etc.)
    ///
    /// # Returns
    /// true if update succeeded
    pub fn update_service(&self, id: i64, opts: Options) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash with symbol keys
        let opts_hash = ruby.hash_new();

        // Add the ID
        let id_sym = ruby.to_symbol("id");
        opts_hash.aset(id_sym, ruby.integer_from_i64(id)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set id: {}", e))
        })?;

        // Add other options
        for (key, value) in opts {
            let key_sym = ruby.to_symbol(&key);
            opts_hash.aset(key_sym, value.into_value_with(&ruby)).map_err(|e| {
                AssassinateError::RubyError(format!("Failed to set option: {}", e))
            })?;
        }

        let result = call_method(*self.ruby_db, "update_service", &[opts_hash.as_value()])?;
        Ok(!result.is_nil())
    }

    /// Delete a service by ID
    pub fn delete_service(&self, id: i64) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        let opts_hash = ruby.hash_new();
        let ids_array = ruby.ary_new();
        ids_array.push(ruby.integer_from_i64(id)).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to push ID: {}", e))
        })?;

        opts_hash.aset(*sym::IDS, ids_array).map_err(|e| {
            AssassinateError::RubyError(format!("Failed to set ids: {}", e))
        })?;

        match call_method(*self.ruby_db, "delete_service", &[opts_hash.as_value()]) {
            Ok(_) => Ok(true),
            Err(_) => {
                match call_method(*self.ruby_db, "delete_services", &[opts_hash.as_value()]) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    // ========== Database Status ==========

    /// Check if database is active/connected
    pub fn active(&self) -> Result<bool> {
        crate::ruby_bridge::get_bool_attr(*self.ruby_db, "active")
    }

    /// Get database driver name
    pub fn driver(&self) -> Result<String> {
        get_string_attr(*self.ruby_db, "driver")
    }

    pub fn __repr__(&self) -> Result<String> {
        let active = self.active().unwrap_or(false);
        Ok(format!("<DbManager active={}>", active))
    }
}
