//! Database manager for Metasploit's database operations

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, is_nil, value_to_string};
use magnus::{value::ReprValue, StaticSymbol, TryConvert, Value};
use std::collections::HashMap;

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
