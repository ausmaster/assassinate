//! Route management through Rex::Socket::SwitchBoard
//!
//! This module provides access to MSF's routing table which allows traffic
//! to be routed through active sessions (pivoting).
//!
//! # Example
//! ```ignore
//! let fw = Framework::new(None)?;
//! let sessions = fw.sessions()?;
//! let session = sessions.get(1)?;
//!
//! // Add route through session
//! fw.route_add("10.10.10.0", "255.255.255.0", 1)?;
//!
//! // List routes
//! for route in fw.route_list()? {
//!     println!("{}/{} via Session {}", route.subnet, route.netmask, route.session_id);
//! }
//!
//! // Remove route
//! fw.route_remove("10.10.10.0", "255.255.255.0", 1)?;
//! ```

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, get_ruby, value_to_string};
use log::{debug, error, info, trace, warn};
use magnus::{value::BoxValue, value::ReprValue, TryConvert, Value};
use serde::{Deserialize, Serialize};

/// Represents a route in the MSF routing table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// The subnet (e.g., "10.10.10.0")
    pub subnet: String,
    /// The netmask (e.g., "255.255.255.0")
    pub netmask: String,
    /// The session ID this route goes through
    pub session_id: Option<i64>,
    /// The comm name (for non-session comms)
    pub comm_name: String,
}

/// Route manager for adding/removing routes through sessions
///
/// Uses `BoxValue` to protect Ruby values from garbage collection.
pub struct RouteManager {
    /// Reference to the SwitchBoard singleton
    pub(crate) ruby_switchboard: BoxValue<Value>,
    /// Reference to sessions manager (for looking up sessions by ID)
    pub(crate) ruby_sessions: BoxValue<Value>,
}

impl RouteManager {
    /// Get the Rex::Socket::SwitchBoard singleton
    pub fn new(ruby_sessions: Value) -> Result<Self> {
        trace!(target: "msf::routing", "Creating RouteManager");
        let ruby = get_ruby()?;

        // Get Rex::Socket::SwitchBoard singleton
        let switchboard = ruby
            .eval::<Value>("Rex::Socket::SwitchBoard")
            .map_err(|e| AssassinateError::RubyError(format!("Failed to get SwitchBoard: {}", e)))?;

        Ok(RouteManager {
            ruby_switchboard: BoxValue::new(switchboard),
            ruby_sessions: BoxValue::new(ruby_sessions),
        })
    }

    /// Add a route through a session
    ///
    /// # Arguments
    /// * `subnet` - The subnet to route (e.g., "10.10.10.0")
    /// * `netmask` - The netmask (e.g., "255.255.255.0" or "24" for CIDR)
    /// * `session_id` - The session ID to route through
    ///
    /// # Returns
    /// `true` if the route was added, `false` if it already exists
    pub fn add_route(&self, subnet: &str, netmask: &str, session_id: i64) -> Result<bool> {
        info!(target: "msf::routing", "Adding route {}/{} via session {}", subnet, netmask, session_id);
        let ruby = get_ruby()?;

        // Get the session object
        let sid_val = ruby.integer_from_i64(session_id).as_value();
        let session = call_method(*self.ruby_sessions, "[]", &[sid_val])?;

        if session.is_nil() {
            error!(target: "msf::routing", "Session {} not found for routing", session_id);
            return Err(AssassinateError::SessionNotFound(session_id));
        }

        let subnet_val = ruby.str_new(subnet).as_value();
        let netmask_val = ruby.str_new(netmask).as_value();

        let result = call_method(
            *self.ruby_switchboard,
            "add_route",
            &[subnet_val, netmask_val, session],
        )?;

        let added = result.to_bool();
        if added {
            info!(target: "msf::routing", "Route added: {}/{} via session {}", subnet, netmask, session_id);
        } else {
            debug!(target: "msf::routing", "Route already exists: {}/{}", subnet, netmask);
        }
        Ok(added)
    }

    /// Remove a route through a session
    ///
    /// # Arguments
    /// * `subnet` - The subnet to remove (e.g., "10.10.10.0")
    /// * `netmask` - The netmask (e.g., "255.255.255.0" or "24" for CIDR)
    /// * `session_id` - The session ID the route goes through
    ///
    /// # Returns
    /// `true` if the route was removed, `false` if it wasn't found
    pub fn remove_route(&self, subnet: &str, netmask: &str, session_id: i64) -> Result<bool> {
        info!(target: "msf::routing", "Removing route {}/{} via session {}", subnet, netmask, session_id);
        let ruby = get_ruby()?;

        // Get the session object
        let sid_val = ruby.integer_from_i64(session_id).as_value();
        let session = call_method(*self.ruby_sessions, "[]", &[sid_val])?;

        if session.is_nil() {
            error!(target: "msf::routing", "Session {} not found for routing", session_id);
            return Err(AssassinateError::SessionNotFound(session_id));
        }

        let subnet_val = ruby.str_new(subnet).as_value();
        let netmask_val = ruby.str_new(netmask).as_value();

        let result = call_method(
            *self.ruby_switchboard,
            "remove_route",
            &[subnet_val, netmask_val, session],
        )?;

        let removed = result.to_bool();
        if removed {
            info!(target: "msf::routing", "Route removed: {}/{}", subnet, netmask);
        } else {
            warn!(target: "msf::routing", "Route not found: {}/{}", subnet, netmask);
        }
        Ok(removed)
    }

    /// List all routes in the routing table
    pub fn list_routes(&self) -> Result<Vec<Route>> {
        debug!(target: "msf::routing", "Listing all routes");
        let _ruby = get_ruby()?;  // Ensure Ruby is initialized
        let mut routes = Vec::new();

        // Get routes array
        let routes_val = call_method(*self.ruby_switchboard, "routes", &[])?;

        // Handle nil/empty case
        if routes_val.is_nil() {
            trace!(target: "msf::routing", "Routes is nil");
            return Ok(routes);
        }

        // routes is an array - iterate over it
        let routes_array: magnus::RArray = match magnus::RArray::from_value(routes_val) {
            Some(arr) => arr,
            None => {
                trace!(target: "msf::routing", "No routes found");
                return Ok(routes);
            }
        };

        for route_obj in routes_array.into_iter() {
            // Extract subnet, netmask, comm from Route object
            let subnet_val = call_method(route_obj, "subnet", &[])?;
            let netmask_val = call_method(route_obj, "netmask", &[])?;
            let comm_val = call_method(route_obj, "comm", &[])?;

            let subnet = value_to_string(subnet_val)?;
            let netmask = value_to_string(netmask_val)?;

            // Check if comm is a Session (has sid method)
            let (session_id, comm_name) = if !comm_val.is_nil() {
                // Try to get session ID
                match call_method(comm_val, "sid", &[]) {
                    Ok(sid_val) => {
                        let sid: i64 = TryConvert::try_convert(sid_val).unwrap_or(0);
                        (Some(sid), format!("Session {}", sid))
                    }
                    Err(_) => {
                        // Not a session - try to get name
                        let name = match call_method(comm_val, "name", &[]) {
                            Ok(name_val) => value_to_string(name_val).unwrap_or_else(|_| "Unknown".to_string()),
                            Err(_) => "Unknown".to_string(),
                        };
                        (None, name)
                    }
                }
            } else {
                (None, "None".to_string())
            };

            routes.push(Route {
                subnet,
                netmask,
                session_id,
                comm_name,
            });
        }

        debug!(target: "msf::routing", "Found {} routes", routes.len());
        Ok(routes)
    }

    /// Flush all routes from the routing table
    pub fn flush_routes(&self) -> Result<()> {
        info!(target: "msf::routing", "Flushing all routes");
        call_method(*self.ruby_switchboard, "flush_routes", &[])?;
        info!(target: "msf::routing", "All routes flushed");
        Ok(())
    }

    /// Check if a route exists
    ///
    /// # Arguments
    /// * `subnet` - The subnet to check
    /// * `netmask` - The netmask
    ///
    /// # Returns
    /// `true` if the route exists, `false` otherwise
    pub fn route_exists(&self, subnet: &str, netmask: &str) -> Result<bool> {
        trace!(target: "msf::routing", "Checking if route {}/{} exists", subnet, netmask);
        let ruby = get_ruby()?;

        let subnet_val = ruby.str_new(subnet).as_value();
        let netmask_val = ruby.str_new(netmask).as_value();

        let result = call_method(
            *self.ruby_switchboard,
            "route_exists?",
            &[subnet_val, netmask_val],
        )?;

        let exists = result.to_bool();
        trace!(target: "msf::routing", "Route {}/{} exists: {}", subnet, netmask, exists);
        Ok(exists)
    }

    /// Find the best session for routing to an address
    ///
    /// # Arguments
    /// * `addr` - The IP address to route to
    ///
    /// # Returns
    /// The session ID if a route exists, None otherwise
    pub fn best_comm(&self, addr: &str) -> Result<Option<i64>> {
        debug!(target: "msf::routing", "Finding best route to {}", addr);
        let ruby = get_ruby()?;

        let addr_val = ruby.str_new(addr).as_value();

        let comm = call_method(*self.ruby_switchboard, "best_comm", &[addr_val])?;

        if comm.is_nil() {
            debug!(target: "msf::routing", "No route to {}", addr);
            return Ok(None);
        }

        // Try to get session ID
        match call_method(comm, "sid", &[]) {
            Ok(sid_val) => {
                let sid: i64 = TryConvert::try_convert(sid_val)
                    .map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
                    })?;
                debug!(target: "msf::routing", "Best route to {} via session {}", addr, sid);
                Ok(Some(sid))
            }
            Err(_) => {
                debug!(target: "msf::routing", "Best comm to {} is not a session", addr);
                Ok(None)
            }
        }
    }

    /// Remove all routes that go through a specific session
    ///
    /// # Arguments
    /// * `session_id` - The session ID to remove routes for
    pub fn remove_by_session(&self, session_id: i64) -> Result<()> {
        info!(target: "msf::routing", "Removing all routes via session {}", session_id);
        let ruby = get_ruby()?;

        // Get the session object
        let sid_val = ruby.integer_from_i64(session_id).as_value();
        let session = call_method(*self.ruby_sessions, "[]", &[sid_val])?;

        if session.is_nil() {
            error!(target: "msf::routing", "Session {} not found", session_id);
            return Err(AssassinateError::SessionNotFound(session_id));
        }

        call_method(*self.ruby_switchboard, "remove_by_comm", &[session])?;
        info!(target: "msf::routing", "All routes via session {} removed", session_id);
        Ok(())
    }

    /// Get the number of routes
    pub fn route_count(&self) -> Result<usize> {
        trace!(target: "msf::routing", "Getting route count");
        let routes = self.list_routes()?;
        trace!(target: "msf::routing", "Route count: {}", routes.len());
        Ok(routes.len())
    }
}

// Note: Tests for routing are in tests/test_route_basic.rs and tests/test_route_integration.rs
// They require Docker containers to be running.
