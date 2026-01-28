//! Python module definition
//!
//! This module defines the `assassinate_pyo3` Python module with:
//! - `PySession` - Wrapper for MSF sessions (shell/meterpreter)
//! - `MsfModule` (exposed as `Module`) - Generic wrapper for all MSF module types
//!   (auxiliary, encoder, evasion, exploit, nop, payload, post)
//! - Module-level functions for framework operations

use std::collections::HashSet;

use pyo3::create_exception;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::AssassinateError as BridgeError;
use crate::ruby_bootstrap::{ensure_ruby, init_ruby, require_all};
use crate::ruby_bridge::{Options, RubyVal};
use crate::{Framework, Module, Session};

use super::conversions::json_to_py;
use super::singleton::{is_initialized, set_framework, with_framework};

// Import macros
use crate::{pyo3_wrap, pyo3_wrap_hashmap, pyo3_wrap_json, pyo3_wrap_json_vec};

// Create custom exception
create_exception!(assassinate, AssassinateError, PyRuntimeError);

// =============================================================================
// PySession - Wrapper for MSF Session
// =============================================================================

/// Python wrapper for Metasploit sessions (shell/meterpreter)
///
/// Provides access to session metadata, shell commands, filesystem operations,
/// process management, system information, network operations, and meterpreter
/// transport management.
#[pyclass(unsendable)]
pub struct PySession {
    pub(crate) session: Session,
}

// Generate wrapper methods via macros
// Each macro generates a separate #[pymethods] impl block (requires multiple-pymethods feature)

// Session Metadata
pyo3_wrap!(PySession, session, session_type() -> String);
pyo3_wrap!(PySession, session, info() -> String);
pyo3_wrap!(PySession, session, alive() -> bool);
pyo3_wrap!(PySession, session, kill() -> ());
pyo3_wrap!(PySession, session, desc() -> String);
pyo3_wrap!(PySession, session, session_host() -> String);
pyo3_wrap!(PySession, session, session_port() -> i64);
pyo3_wrap!(PySession, session, tunnel_peer() -> String);
pyo3_wrap!(PySession, session, target_host() -> String);
pyo3_wrap!(PySession, session, via_exploit() -> String);
pyo3_wrap!(PySession, session, via_payload() -> String);

// Shell Session
pyo3_wrap!(PySession, session, shell_read() -> String);
pyo3_wrap!(PySession, session, shell_write(data: &str) -> usize);

// Meterpreter Filesystem
pyo3_wrap!(PySession, session, fs_pwd() -> String);
pyo3_wrap!(PySession, session, fs_chdir(path: &str) -> ());
pyo3_wrap!(PySession, session, fs_ls(path: &str) -> Vec<String>);
pyo3_wrap!(PySession, session, fs_mkdir(path: &str) -> ());
pyo3_wrap!(PySession, session, fs_rmdir(path: &str) -> ());
pyo3_wrap!(PySession, session, fs_exists(path: &str) -> bool);
pyo3_wrap!(PySession, session, fs_rm(path: &str) -> ());
pyo3_wrap!(PySession, session, fs_mv(old_path: &str, new_path: &str) -> ());
pyo3_wrap!(PySession, session, fs_cp(src_path: &str, dst_path: &str) -> ());
pyo3_wrap!(PySession, session, fs_separator() -> String);
pyo3_wrap!(PySession, session, fs_expand_path(path: &str) -> String);
pyo3_wrap!(PySession, session, fs_download_file(local_path: &str, remote_path: &str) -> String);
pyo3_wrap!(PySession, session, fs_upload_file(remote_path: &str, local_path: &str) -> ());
pyo3_wrap_json!(PySession, session, fs_stat(path: &str));
// Meterpreter gap methods (4.5D)
pyo3_wrap!(PySession, session, fs_md5(path: &str) -> String);
pyo3_wrap!(PySession, session, fs_sha1(path: &str) -> String);

// Meterpreter Process
pyo3_wrap!(PySession, session, process_getpid() -> i64);
pyo3_wrap!(PySession, session, process_kill(pid: i64) -> ());
pyo3_wrap!(PySession, session, process_open(pid: i64, perms: i64) -> i64);
pyo3_wrap_json_vec!(PySession, session, process_list());

// Meterpreter System
pyo3_wrap!(PySession, session, sys_getuid() -> String);
pyo3_wrap!(PySession, session, sys_getsid() -> String);
pyo3_wrap!(PySession, session, sys_is_system() -> bool);
pyo3_wrap!(PySession, session, sys_localtime() -> String);
pyo3_wrap!(PySession, session, sys_getprivs() -> Vec<String>);
pyo3_wrap_json!(PySession, session, sys_sysinfo());
pyo3_wrap!(PySession, session, sys_steal_token(pid: i64) -> bool);
pyo3_wrap_json_vec!(PySession, session, sys_getdrivers());

// Meterpreter Network
pyo3_wrap_json_vec!(PySession, session, net_get_interfaces());
pyo3_wrap_json_vec!(PySession, session, net_get_routes());
pyo3_wrap_json_vec!(PySession, session, net_get_arp_table());
pyo3_wrap_json_vec!(PySession, session, net_get_netstat());
pyo3_wrap_json!(PySession, session, net_get_proxy_config());
pyo3_wrap!(PySession, session, net_add_route(subnet: &str, netmask: &str, gateway: &str) -> ());
pyo3_wrap!(PySession, session, net_remove_route(subnet: &str, netmask: &str, gateway: &str) -> ());

// Meterpreter Core
pyo3_wrap!(PySession, session, meterpreter_shutdown() -> bool);
pyo3_wrap!(PySession, session, meterpreter_use(extension_name: &str) -> bool);
pyo3_wrap!(PySession, session, meterpreter_secure() -> bool);

// Meterpreter Transport
pyo3_wrap_json!(PySession, session, transport_list());
pyo3_wrap!(PySession, session, transport_sleep(seconds: u32) -> bool);
pyo3_wrap!(PySession, session, transport_next() -> bool);
pyo3_wrap!(PySession, session, transport_prev() -> bool);

// Response Timeout
pyo3_wrap!(PySession, session, get_response_timeout() -> u32);
pyo3_wrap!(PySession, session, set_response_timeout(timeout_secs: u32) -> ());

// Manual implementations for methods with complex signatures
#[pymethods]
impl PySession {
    /// Execute a shell command with optional timeout
    fn run_cmd(&self, cmd: &str, timeout: Option<u32>) -> PyResult<String> {
        Ok(self.session.run_cmd(cmd, timeout)?)
    }

    /// Read from the session with optional length limit
    fn read(&self, length: Option<usize>) -> PyResult<String> {
        Ok(self.session.read(length)?)
    }

    /// Write data to the session
    fn write(&self, data: &str) -> PyResult<usize> {
        Ok(self.session.write(data)?)
    }

    /// Get the session ID
    fn sid(&self) -> i64 {
        self.session.session_id
    }

    /// Upgrade a shell session to meterpreter
    fn shell_to_meterpreter(&self, lhost: &str, lport: u16) -> PyResult<bool> {
        Ok(self.session.shell_to_meterpreter(lhost, lport, None)?)
    }

    /// Execute a process on the target
    fn process_execute(
        &self,
        py: Python<'_>,
        path: &str,
        args: &str,
        hidden: Option<bool>,
        channelized: Option<bool>,
    ) -> PyResult<PyObject> {
        let value = self.session.process_execute(
            path,
            args,
            hidden.unwrap_or(false),
            channelized.unwrap_or(false),
        )?;
        json_to_py(py, &value)
    }

    /// Get an environment variable
    fn sys_getenv(&self, var_name: &str) -> PyResult<Option<String>> {
        Ok(self.session.sys_getenv(var_name)?)
    }

    /// Search for files matching a pattern
    fn fs_search(
        &self,
        py: Python<'_>,
        root: &str,
        pattern: &str,
        recurse: Option<bool>,
    ) -> PyResult<PyObject> {
        let results = self.session.fs_search(root, pattern, recurse.unwrap_or(true))?;
        json_to_py(py, &serde_json::json!(results))
    }

    /// Get multiple environment variables
    fn sys_getenvs(&self, py: Python<'_>, var_names: Vec<String>) -> PyResult<PyObject> {
        let map = self.session.sys_getenvs(var_names)?;
        let dict = PyDict::new_bound(py);
        for (k, v) in map {
            dict.set_item(k, v)?;
        }
        Ok(dict.into())
    }

    /// Get the machine ID (with optional timeout)
    fn meterpreter_machine_id(&self, timeout: Option<u32>) -> PyResult<String> {
        Ok(self.session.meterpreter_machine_id(timeout)?)
    }

    /// Get the native architecture (with optional timeout)
    fn meterpreter_native_arch(&self, timeout: Option<u32>) -> PyResult<String> {
        Ok(self.session.meterpreter_native_arch(timeout)?)
    }

    /// Get the session GUID (with optional timeout)
    fn meterpreter_session_guid(&self, timeout: Option<u32>) -> PyResult<String> {
        Ok(self.session.meterpreter_session_guid(timeout)?)
    }

    /// Migrate to another process
    fn meterpreter_migrate(
        &self,
        target_pid: i64,
        writable_dir: Option<&str>,
        timeout: Option<u32>,
    ) -> PyResult<bool> {
        Ok(self
            .session
            .meterpreter_migrate(target_pid, writable_dir, timeout)?)
    }

    /// Set transport timeouts
    fn set_transport_timeouts(
        &self,
        py: Python<'_>,
        session_exp: Option<i64>,
        comm_timeout: Option<i64>,
        retry_total: Option<i64>,
        retry_wait: Option<i64>,
    ) -> PyResult<PyObject> {
        let value = self
            .session
            .set_transport_timeouts(session_exp, comm_timeout, retry_total, retry_wait)?;
        json_to_py(py, &value)
    }

    /// Add a transport
    #[pyo3(signature = (transport, lport, lhost=None, ua=None, comm_timeout=None, session_exp=None, retry_total=None, retry_wait=None))]
    fn transport_add(
        &self,
        transport: &str,
        lport: u16,
        lhost: Option<&str>,
        ua: Option<&str>,
        comm_timeout: Option<i64>,
        session_exp: Option<i64>,
        retry_total: Option<i64>,
        retry_wait: Option<i64>,
    ) -> PyResult<bool> {
        Ok(self.session.transport_add(
            transport,
            lhost,
            lport,
            ua,
            comm_timeout,
            session_exp,
            retry_total,
            retry_wait,
        )?)
    }

    /// Remove a transport
    #[pyo3(signature = (transport, lport, lhost=None))]
    fn transport_remove(&self, transport: &str, lport: u16, lhost: Option<&str>) -> PyResult<bool> {
        Ok(self.session.transport_remove(transport, lhost, lport)?)
    }

    /// Change to a different transport
    #[pyo3(signature = (transport, lport, lhost=None))]
    fn transport_change(&self, transport: &str, lport: u16, lhost: Option<&str>) -> PyResult<bool> {
        Ok(self.session.transport_change(transport, lhost, lport)?)
    }

    /// Run a post-exploitation module
    fn run_post_module(
        &self,
        module_path: &str,
        options: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<bool> {
        let mut opts = Options::new();
        if let Some(py_opts) = options {
            for (key, value) in py_opts.iter() {
                let key_str: String = key.extract()?;
                if let Ok(val) = value.extract::<bool>() {
                    opts.insert(key_str, RubyVal::Bool(val));
                } else if let Ok(val) = value.extract::<i64>() {
                    opts.insert(key_str, RubyVal::Int(val));
                } else if let Ok(val) = value.extract::<String>() {
                    opts.insert(key_str, RubyVal::String(val));
                }
            }
        }
        Ok(self.session.run_post_module(module_path, opts)?)
    }
}

// =============================================================================
// MsfModule - Generic Wrapper for all MSF Module Types
// =============================================================================

/// Python wrapper for Metasploit modules (all 7 types: auxiliary, encoder, evasion, exploit, nop, payload, post)
///
/// Provides access to module metadata, options configuration, validation,
/// and type-specific execution methods. The Python layer uses type-specific
/// subclasses (ExploitModule, AuxiliaryModule, etc.) that wrap this generic class.
#[pyclass(unsendable, name = "Module")]
pub struct MsfModule {
    pub(crate) module: Module,
    pub(crate) fullname: String,
}

// Generate wrapper methods via macros
// Module Metadata
pyo3_wrap!(MsfModule, module, description() -> String);
pyo3_wrap!(MsfModule, module, author() -> Vec<String>);
pyo3_wrap!(MsfModule, module, references() -> Vec<String>);
pyo3_wrap!(MsfModule, module, platform() -> Vec<String>);
pyo3_wrap!(MsfModule, module, arch() -> Vec<String>);
pyo3_wrap!(MsfModule, module, rank() -> String);
pyo3_wrap!(MsfModule, module, license() -> String);
pyo3_wrap!(MsfModule, module, disclosure_date() -> Option<String>);
pyo3_wrap!(MsfModule, module, privileged() -> bool);
pyo3_wrap!(MsfModule, module, targets() -> Vec<String>);
pyo3_wrap!(MsfModule, module, aliases() -> Vec<String>);
pyo3_wrap!(MsfModule, module, action() -> Option<String>);
pyo3_wrap_hashmap!(MsfModule, module, notes());

// Note: Options are accessed via Python wrapper's ModuleOptions class
// which uses _get_option, _set_option, _options_structured, _missing_required
// (defined in the manual implementations below)

// Validation
pyo3_wrap!(MsfModule, module, validate() -> bool);
pyo3_wrap!(MsfModule, module, has_check() -> bool);
pyo3_wrap!(MsfModule, module, check() -> String);

// Compatibility
pyo3_wrap!(MsfModule, module, compatible_payloads() -> Vec<String>);
pyo3_wrap!(MsfModule, module, actions() -> Vec<String>);
pyo3_wrap!(MsfModule, module, default_action() -> Option<String>);

// Manual implementations for complex methods
#[pymethods]
impl MsfModule {
    /// Get the module type (auxiliary, encoder, evasion, exploit, nop, payload, post)
    fn module_type(&self) -> PyResult<String> {
        Ok(self.module.module_type()?)
    }

    /// Execute the exploit
    ///
    /// # Arguments
    /// * `payload` - Payload name (e.g., "cmd/unix/interact")
    /// * `timeout_secs` - Seconds to wait for session (ignored if job=true)
    /// * `job` - If true, run as background job and return job ID immediately
    ///
    /// # Returns
    /// * If job=false: PySession if successful, None otherwise
    /// * If job=true: Job ID (str) if job started, None otherwise
    #[pyo3(signature = (payload, timeout_secs=60, job=false))]
    fn exploit(
        &self,
        py: Python<'_>,
        payload: &str,
        timeout_secs: u64,
        job: bool,
    ) -> PyResult<PyObject> {
        let framework = self.module.framework()?;

        if job {
            // Run as background job - return job ID immediately
            let mut options = Options::new();
            options.insert("RunAsJob".into(), RubyVal::Bool(true));

            let jobs_before: Vec<String> = framework.jobs()?.list()?;
            let _ = self.module.exploit(payload, Some(options))?;
            let jobs_after: Vec<String> = framework.jobs()?.list()?;

            // Find new job ID
            for job_id in jobs_after {
                if !jobs_before.contains(&job_id) {
                    return Ok(job_id.into_py(py));
                }
            }
            Ok(py.None())
        } else {
            // Wait for session
            let session_manager = framework.sessions()?;
            // Use HashSet for O(1) lookups instead of Vec's O(n) contains()
            let sessions_before: HashSet<i64> = session_manager.list()?.into_iter().collect();

            let mut options = Options::new();
            options.insert("Quiet".into(), RubyVal::Bool(false));
            // AutoVerifySession ensures session is valid before exploit_simple returns
            options.insert("AutoVerifySession".into(), RubyVal::Bool(true));

            // Try to get session directly from exploit (some exploits return it immediately)
            if let Some(sid) = self.module.exploit(payload, Some(options))? {
                if let Some(s) = session_manager.get(sid)? {
                    return Ok(PySession { session: s }.into_py(py));
                }
            }

            // Poll for new sessions, releasing GVL between checks
            let mut found_session: Option<PySession> = None;
            let timeout_ms = timeout_secs * 1000;

            crate::gvl::poll_releasing_gvl(
                || {
                    if let Ok(sessions_now) = session_manager.list() {
                        for sid in sessions_now {
                            // HashSet.contains() is O(1) vs Vec's O(n)
                            if !sessions_before.contains(&sid) {
                                if let Ok(Some(s)) = session_manager.get(sid) {
                                    found_session = Some(PySession { session: s });
                                    return true;
                                }
                            }
                        }
                    }
                    false
                },
                Some(1000),
                Some(timeout_ms),
            );

            match found_session {
                Some(session) => Ok(session.into_py(py)),
                None => Ok(py.None()),
            }
        }
    }

    /// Run an auxiliary module
    fn run(&self) -> PyResult<bool> {
        Ok(self.module.run(None)?)
    }

    /// Get the full module name (e.g., "exploit/linux/samba/is_known_pipename")
    fn fullname(&self) -> String {
        self.fullname.clone()
    }

    /// Get structured options with metadata (for Python wrapper)
    fn _options_structured(&self, py: Python<'_>) -> PyResult<PyObject> {
        let opts = self.module.options_structured()?;
        let dict = PyDict::new_bound(py);
        for (key, value) in opts {
            let py_value = json_to_py(py, &value)?;
            dict.set_item(key, py_value)?;
        }
        Ok(dict.into())
    }

    /// Get an option value (for Python wrapper)
    fn _get_option(&self, key: &str) -> PyResult<Option<String>> {
        Ok(self.module.get_option(key)?)
    }

    /// Set an option value (for Python wrapper)
    fn _set_option(&self, key: &str, value: &str) -> PyResult<()> {
        Ok(self.module.set_option(key, value)?)
    }

    /// Get missing required options (for Python wrapper)
    fn _missing_required(&self) -> PyResult<Vec<String>> {
        Ok(self.module.missing_required()?)
    }

    // ========== Exploit Target Constraints (4.5C) ==========

    /// Get available payload space for current target
    fn payload_space(&self) -> PyResult<Option<i64>> {
        Ok(self.module.payload_space()?)
    }

    /// Get bad characters to avoid in payloads for current target
    fn payload_badchars(&self, py: Python<'_>) -> PyResult<PyObject> {
        use pyo3::types::PyBytes;
        let badchars = self.module.payload_badchars()?;
        Ok(PyBytes::new_bound(py, &badchars).into())
    }

    /// Get platform of current target
    fn target_platform(&self) -> PyResult<Option<String>> {
        Ok(self.module.target_platform()?)
    }

    /// Get architecture of current target
    fn target_arch(&self) -> PyResult<Option<String>> {
        Ok(self.module.target_arch()?)
    }

    /// Get current target index
    fn target_index(&self) -> PyResult<Option<i64>> {
        Ok(self.module.target_index()?)
    }

    /// Perform detailed vulnerability check
    fn check_detailed(&self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.module.check_detailed()?;
        json_to_py(py, &result)
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
    /// NOP sled bytes as PyBytes
    #[pyo3(signature = (length, badchars=None, save_registers=None))]
    fn generate_sled(
        &self,
        py: Python<'_>,
        length: i32,
        badchars: Option<Vec<u8>>,
        save_registers: Option<Vec<String>>,
    ) -> PyResult<PyObject> {
        use pyo3::types::PyBytes;

        let sled = self.module.generate_sled(length, badchars.as_deref(), save_registers)?;
        Ok(PyBytes::new_bound(py, &sled).into())
    }
}

// =============================================================================
// Module Functions
// =============================================================================

/// Internal helper to initialize MSF environment
fn init_msf_generic(msf_root: &str) -> Result<(), BridgeError> {
    let lib_path = format!("{}/lib", msf_root);
    let gemfile_path = format!("{}/Gemfile", msf_root);
    let boot_path = format!("{}/config/boot", msf_root);

    ensure_ruby()?;

    init_ruby(
        &[lib_path],
        &[
            (String::from("BUNDLE_GEMFILE"), gemfile_path),
            (String::from("RAILS_ENV"), String::from("production")),
        ],
    )?;

    let requires = vec![boot_path, String::from("msfenv")];
    require_all(&requires).map_err(|e| BridgeError::RubyError(e.to_string()))
}

/// Initialize the Metasploit Framework
///
/// Must be called before any other functions. Sets up the Ruby VM,
/// loads MSF libraries, and creates the Framework singleton.
///
/// # Arguments
///
/// * `msf_root` - Path to the Metasploit Framework installation
#[pyfunction]
fn init_msf(msf_root: &str) -> PyResult<()> {
    init_msf_generic(msf_root)?;

    if !is_initialized() {
        let framework = Framework::new(None)?;
        set_framework(framework);
    }

    Ok(())
}

/// Check if the Framework has been initialized
#[pyfunction]
#[pyo3(name = "is_initialized")]
fn pyo3_is_initialized() -> bool {
    is_initialized()
}

/// Get the Metasploit Framework version
#[pyfunction]
fn framework_version() -> PyResult<String> {
    Ok(with_framework(|fw| fw.version())?)
}

/// Get module statistics (counts by type)
///
/// Returns a dictionary mapping module types to their counts.
///
/// Example:
///     {"exploits": 2500, "auxiliary": 1200, "post": 400, ...}
#[pyfunction]
fn module_stats(py: Python<'_>) -> PyResult<PyObject> {
    let stats = with_framework(|fw| fw.module_stats())?;
    json_to_py(py, &serde_json::json!(stats))
}

/// Add a custom module path to the framework
///
/// The path must contain top-level directories for module types
/// (exploits, auxiliary, post, encoders, nops, payloads, evasion).
///
/// Returns a dictionary with counts of modules loaded from the new path.
#[pyfunction]
fn add_module_path(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let stats = with_framework(|fw| fw.add_module_path(path))?;
    json_to_py(py, &serde_json::json!(stats))
}

/// Hot reload all framework modules
///
/// Reloads all modules from their source files, picking up any changes.
///
/// Returns a dictionary with counts of modules reloaded by type.
#[pyfunction]
fn reload_modules(py: Python<'_>) -> PyResult<PyObject> {
    let stats = with_framework(|fw| fw.reload_modules())?;
    json_to_py(py, &serde_json::json!(stats))
}

/// List all modules of a given type
///
/// # Arguments
///
/// * `module_type` - One of: "exploit", "auxiliary", "post", "payload", "encoder", "nop"
#[pyfunction]
fn list_modules(module_type: &str) -> PyResult<Vec<String>> {
    Ok(with_framework(|fw| fw.list_modules(module_type))?)
}

/// Get basic module information
#[pyfunction]
fn get_module_info(module_name: &str, py: Python<'_>) -> PyResult<PyObject> {
    let info = with_framework(|framework| {
        let module = framework.create_module(module_name)?;

        let fullname = module.fullname()?;
        let description = module.description()?;
        let mtype = module.module_type()?;

        Ok((fullname, description, mtype))
    })?;

    let dict = PyDict::new_bound(py);
    dict.set_item("fullname", &info.0)?;
    dict.set_item(
        "description",
        if info.1.is_empty() { "N/A" } else { &info.1 },
    )?;
    dict.set_item("module_type", info.2)?;
    dict.set_item("name", info.0.split('/').last().unwrap_or(""))?;

    Ok(dict.into())
}

/// Create a module instance by name
///
/// # Arguments
///
/// * `module_name` - Full module path (e.g., "exploit/linux/samba/is_known_pipename")
#[pyfunction]
fn create_module(module_name: &str) -> PyResult<MsfModule> {
    let (module, fullname) = with_framework(|framework| {
        let module = framework.create_module(module_name)?;
        let fullname = module.fullname()?;
        Ok((module, fullname))
    })?;

    Ok(MsfModule { module, fullname })
}

/// Quick exploit execution (creates module, runs exploit, returns session ID)
#[pyfunction]
fn exploit(module_fullname: &str, payload: &str) -> PyResult<Option<i64>> {
    Ok(with_framework(|framework| {
        let module = framework.create_module(module_fullname)?;
        module.exploit(payload, None)
    })?)
}

/// Quick check execution (creates module, runs check, returns result)
#[pyfunction]
fn check(module_fullname: &str) -> PyResult<String> {
    Ok(with_framework(|framework| {
        let module = framework.create_module(module_fullname)?;
        module.check()
    })?)
}

/// List all active session IDs
#[pyfunction]
fn list_sessions() -> PyResult<Vec<i64>> {
    Ok(with_framework(|framework| {
        let session_manager = framework.sessions()?;
        session_manager.list()
    })?)
}

/// Search for modules matching a query
#[pyfunction]
fn search(query: &str) -> PyResult<Vec<String>> {
    Ok(with_framework(|fw| fw.search(query))?)
}

/// Get a session by ID
#[pyfunction]
fn get_session(session_id: i64) -> PyResult<Option<PySession>> {
    let session = with_framework(|framework| {
        let session_manager = framework.sessions()?;
        session_manager.get(session_id)
    })?;

    Ok(session.map(|s| PySession { session: s }))
}

/// Kill a session by ID
#[pyfunction]
fn kill_session(session_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let session_manager = framework.sessions()?;
        session_manager.kill(session_id)
    })?)
}

/// Create a shell session from a raw bind shell
///
/// Connects to a bind shell (like netcat or socat) and creates an MSF session.
/// This is useful for integrating with pre-existing shells or testing.
///
/// # Arguments
///
/// * `host` - Target host running the bind shell
/// * `port` - Port the bind shell is listening on
/// * `timeout` - Connection timeout in seconds
///
/// # Returns
///
/// Session ID on success
#[pyfunction]
fn create_shell_session(host: &str, port: u16, timeout: Option<u32>) -> PyResult<i64> {
    Ok(with_framework(|framework| {
        let session_manager = framework.sessions()?;
        session_manager.create_shell_session(host, port, timeout.unwrap_or(30))
    })?)
}

/// Poll for a condition while releasing the Ruby GVL between checks.
///
/// This is the primary mechanism for waiting on Ruby background operations.
/// It releases the GVL during sleep intervals, allowing Ruby threads to run.
///
/// Args:
///     check_fn: Callable that returns True when condition is met
///     interval_ms: Sleep interval between checks (default: 100ms)
///     timeout_ms: Total timeout in ms (default: 60000ms, 0 = no timeout)
///
/// Returns:
///     True if condition was met, False if timeout
///
/// Example:
///     >>> # Wait for a session to appear
///     >>> found = poll_releasing_gvl(
///     ...     lambda: len(list_sessions()) > 0,
///     ...     interval_ms=100,
///     ...     timeout_ms=30000
///     ... )
#[pyfunction]
#[pyo3(signature = (check_fn, interval_ms=None, timeout_ms=None))]
fn poll_releasing_gvl(
    _py: Python<'_>,
    check_fn: PyObject,
    interval_ms: Option<u64>,
    timeout_ms: Option<u64>,
) -> PyResult<bool> {
    let result = crate::gvl::poll_releasing_gvl(
        || {
            // Call the Python check function
            Python::with_gil(|py| {
                check_fn
                    .call0(py)
                    .and_then(|result| result.extract::<bool>(py))
                    .unwrap_or(false)
            })
        },
        interval_ms,
        timeout_ms,
    );
    Ok(result)
}

/// Sleep while releasing the Ruby GVL.
///
/// Convenience wrapper for simple sleep without a condition check.
/// Useful for allowing Ruby background threads to run.
///
/// Args:
///     duration_ms: How long to sleep in milliseconds
#[pyfunction]
fn sleep_releasing_gvl(duration_ms: u64) {
    crate::gvl::sleep_releasing_gvl(duration_ms);
}

/// List all job IDs
#[pyfunction]
fn job_list() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let jobs = framework.jobs()?;
        jobs.list()
    })?)
}

/// Get information about a job
#[pyfunction]
fn job_info(job_id: &str) -> PyResult<Option<String>> {
    Ok(with_framework(|framework| {
        let jobs = framework.jobs()?;
        jobs.get(job_id)
    })?)
}

/// Kill a job by ID
///
/// Accepts either a string or integer job ID for convenience.
#[pyfunction]
fn job_kill(py: Python<'_>, job_id: PyObject) -> PyResult<bool> {
    // Convert job_id to string, accepting both int and str
    let job_id_str: String = if let Ok(s) = job_id.extract::<String>(py) {
        s
    } else if let Ok(i) = job_id.extract::<i64>(py) {
        i.to_string()
    } else {
        return Err(PyRuntimeError::new_err(
            "job_id must be a string or integer",
        ));
    };

    Ok(with_framework(|framework| {
        let jobs = framework.jobs()?;
        jobs.kill(&job_id_str)
    })?)
}

/// Wait for a session from an exploit job using MSF's native event mechanism.
///
/// This is the CORRECT way to wait for a session from a background job.
/// It uses MSF's internal `payload.wait_for_session()` which blocks on the
/// `session_waiter_event`. This event is only notified AFTER bootstrap completes,
/// guaranteeing the session is fully ready for commands.
///
/// Unlike polling `list_sessions()`, this approach:
/// - Waits for the session to be FULLY initialized (bootstrap complete)
/// - Uses MSF's native event mechanism (Rex::Sync::Event)
/// - Releases the GVL internally, allowing Ruby threads to execute
///
/// # Arguments
/// * `job_id` - The exploit job ID to wait on (string or int)
/// * `timeout_secs` - Timeout in seconds (default: 60)
///
/// # Returns
/// * Session ID if session was created
/// * None if timeout waiting for session
///
/// # Raises
/// * RuntimeError if job not found or doesn't support wait_for_session
#[pyfunction]
#[pyo3(signature = (job_id, timeout_secs=None))]
fn job_wait_for_session(py: Python<'_>, job_id: PyObject, timeout_secs: Option<u32>) -> PyResult<Option<i64>> {
    // Convert job_id to string, accepting both int and str
    let job_id_str: String = if let Ok(s) = job_id.extract::<String>(py) {
        s
    } else if let Ok(i) = job_id.extract::<i64>(py) {
        i.to_string()
    } else {
        return Err(PyRuntimeError::new_err(
            "job_id must be a string or integer",
        ));
    };

    Ok(with_framework(|framework| {
        let jobs = framework.jobs()?;
        jobs.wait_for_session(&job_id_str, timeout_secs)
    })?)
}

// =============================================================================
// Payload Generation Functions (Tier 2)
// =============================================================================

/// Generate raw payload bytes
///
/// # Arguments
///
/// * `payload_name` - Full payload path (e.g., "linux/x64/meterpreter/reverse_tcp")
/// * `options` - Optional dict of payload options (LHOST, LPORT, etc.)
///
/// # Returns
///
/// Raw shellcode bytes as `PyBytes`
#[pyfunction]
#[pyo3(signature = (payload_name, options=None))]
fn forge_payload(
    py: Python<'_>,
    payload_name: &str,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyObject> {
    use crate::framework::PayloadGenerator;
    use pyo3::types::PyBytes;

    let opts = pydict_to_options(options)?;

    let bytes = with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.generate(payload_name, opts)
    })?;

    Ok(PyBytes::new_bound(py, &bytes).into())
}

/// Generate encoded payload bytes
///
/// # Arguments
///
/// * `payload_name` - Full payload path (e.g., "windows/meterpreter/reverse_tcp")
/// * `encoder` - Optional encoder (e.g., "x86/shikata_ga_nai")
/// * `iterations` - Optional number of encoding iterations
/// * `options` - Optional dict of payload options (LHOST, LPORT, etc.)
///
/// # Returns
///
/// Encoded shellcode bytes as `PyBytes`
#[pyfunction]
#[pyo3(signature = (payload_name, encoder=None, iterations=None, options=None))]
fn forge_encoded(
    py: Python<'_>,
    payload_name: &str,
    encoder: Option<&str>,
    iterations: Option<i32>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyObject> {
    use crate::framework::PayloadGenerator;
    use pyo3::types::PyBytes;

    let opts = pydict_to_options(options)?;

    let bytes = with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.generate_encoded(payload_name, encoder, iterations, opts)
    })?;

    Ok(PyBytes::new_bound(py, &bytes).into())
}

/// Generate a standalone executable payload
///
/// # Arguments
///
/// * `payload_name` - Full payload path (e.g., "windows/x64/meterpreter/reverse_https")
/// * `platform` - Target platform ("windows", "linux", "osx")
/// * `arch` - Target architecture ("x86", "x64")
/// * `options` - Optional dict of payload options (LHOST, LPORT, etc.)
///
/// # Returns
///
/// Executable bytes as `PyBytes`
#[pyfunction]
#[pyo3(signature = (payload_name, platform, arch, options=None))]
fn forge_executable(
    py: Python<'_>,
    payload_name: &str,
    platform: &str,
    arch: &str,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyObject> {
    use crate::framework::PayloadGenerator;
    use pyo3::types::PyBytes;

    let opts = pydict_to_options(options)?;

    let bytes = with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.generate_executable(payload_name, platform, arch, opts)
    })?;

    Ok(PyBytes::new_bound(py, &bytes).into())
}

/// List all available payloads
///
/// # Returns
///
/// List of payload reference names
#[pyfunction]
fn list_payloads() -> PyResult<Vec<String>> {
    use crate::framework::PayloadGenerator;

    Ok(with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.list_payloads()
    })?)
}

/// Generate a payload in a specific output format.
///
/// Transforms raw shellcode into language-specific formats like C arrays,
/// Python bytes, Ruby strings, etc.
///
/// # Arguments
///
/// * `payload_name` - Full payload path (e.g., "linux/x86/shell_reverse_tcp")
/// * `format` - Output format: raw, hex, c, python, ruby, bash, perl, csharp, java, go, rust, powershell, base64, num, dword, js_le, js_be
/// * `var_name` - Optional variable name (default: "buf")
/// * `options` - Optional dict of payload options (LHOST, LPORT, etc.)
///
/// # Returns
///
/// Formatted string representation of the payload
#[pyfunction]
#[pyo3(signature = (payload_name, format, var_name=None, options=None))]
fn forge_formatted(
    payload_name: &str,
    format: &str,
    var_name: Option<&str>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<String> {
    use crate::framework::PayloadGenerator;

    let opts = pydict_to_options(options)?;

    let formatted = with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.generate_formatted(payload_name, format, var_name, opts)
    })?;

    Ok(formatted)
}

/// Transform raw bytes to a specific output format.
///
/// This is a standalone function that transforms existing bytes without
/// generating a new payload.
///
/// # Arguments
///
/// * `buf` - Raw bytes to transform
/// * `format` - Output format (see forge_formatted for list)
/// * `var_name` - Optional variable name (default: "buf")
///
/// # Returns
///
/// Formatted string representation
#[pyfunction]
#[pyo3(signature = (buf, format, var_name=None))]
fn transform_buffer(buf: &[u8], format: &str, var_name: Option<&str>) -> PyResult<String> {
    use crate::framework::PayloadGenerator;

    let name = var_name.unwrap_or("buf");
    let formatted = PayloadGenerator::transform_buffer(buf, format, name)?;
    Ok(formatted)
}

/// Generate payload with automatic encoder selection to avoid bad characters.
///
/// This implements MSF's encoder auto-selection logic:
/// 1. Generate raw payload
/// 2. Check if badchars actually exist in payload (skip encoding if not)
/// 3. Get compatible encoders ranked by arch/platform
/// 4. Try each encoder in ranked order until payload is clean
///
/// # Arguments
///
/// * `payload_name` - Full payload path (e.g., "linux/x86/shell_reverse_tcp")
/// * `badchars` - Bytes to avoid in final payload (e.g., b"\x00\x0a\x0d")
/// * `iterations` - Optional number of encoding iterations (default: 1)
/// * `options` - Optional dict of payload options (LHOST, LPORT, etc.)
///
/// # Returns
///
/// Tuple of (encoded payload bytes, encoder name used or None if no encoding needed)
///
/// # Raises
///
/// AssassinateError if no encoder can clean the payload
#[pyfunction]
#[pyo3(signature = (payload_name, badchars, iterations=None, options=None))]
fn forge_payload_with_badchars(
    py: Python<'_>,
    payload_name: &str,
    badchars: &[u8],
    iterations: Option<i32>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<(PyObject, Option<String>)> {
    use crate::framework::PayloadGenerator;
    use pyo3::types::PyBytes;

    let opts = pydict_to_options(options)?;

    let (bytes, encoder_used) = with_framework(|framework| {
        let generator = PayloadGenerator::new(framework)?;
        generator.generate_with_badchars(payload_name, badchars, iterations, opts)
    })?;

    Ok((PyBytes::new_bound(py, &bytes).into(), encoder_used))
}

/// Helper to convert Python dict to Options HashMap
fn pydict_to_options(options: Option<&Bound<'_, PyDict>>) -> PyResult<Option<Options>> {
    match options {
        Some(py_opts) => {
            let mut opts = Options::new();
            for (key, value) in py_opts.iter() {
                let key_str: String = key.extract()?;
                if let Ok(val) = value.extract::<bool>() {
                    opts.insert(key_str, RubyVal::Bool(val));
                } else if let Ok(val) = value.extract::<i64>() {
                    opts.insert(key_str, RubyVal::Int(val));
                } else if let Ok(val) = value.extract::<String>() {
                    opts.insert(key_str, RubyVal::String(val));
                }
            }
            Ok(Some(opts))
        }
        None => Ok(None),
    }
}

// =============================================================================
// Database Functions (Tier 3)
// =============================================================================

/// Check if database is active/connected
#[pyfunction]
fn db_active() -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.active()
    })?)
}

/// Get database driver name
#[pyfunction]
fn db_driver() -> PyResult<String> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.driver()
    })?)
}

/// Get all hosts from database
#[pyfunction]
fn db_hosts() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.hosts()
    })?)
}

/// Get all services from database
#[pyfunction]
fn db_services() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.services()
    })?)
}

/// Get all vulnerabilities from database
#[pyfunction]
fn db_vulns() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.vulns()
    })?)
}

/// Get all credentials from database
#[pyfunction]
fn db_creds() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.creds()
    })?)
}

/// Get all loot from database
#[pyfunction]
fn db_loot() -> PyResult<Vec<String>> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.loot()
    })?)
}

/// Report a host to the database
#[pyfunction]
#[pyo3(signature = (options=None))]
fn db_report_host(options: Option<&Bound<'_, PyDict>>) -> PyResult<i64> {
    let opts = pydict_to_options(options)?;
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.report_host(opts)
    })?)
}

/// Report a service to the database
#[pyfunction]
#[pyo3(signature = (options=None))]
fn db_report_service(options: Option<&Bound<'_, PyDict>>) -> PyResult<i64> {
    let opts = pydict_to_options(options)?;
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.report_service(opts)
    })?)
}

/// Report a vulnerability to the database
#[pyfunction]
#[pyo3(signature = (options=None))]
fn db_report_vuln(options: Option<&Bound<'_, PyDict>>) -> PyResult<i64> {
    let opts = pydict_to_options(options)?;
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.report_vuln(opts)
    })?)
}

/// Report a credential to the database
#[pyfunction]
#[pyo3(signature = (options=None))]
fn db_report_cred(options: Option<&Bound<'_, PyDict>>) -> PyResult<i64> {
    let opts = pydict_to_options(options)?;
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.report_cred(opts)
    })?)
}

/// List all workspaces
#[pyfunction]
fn db_workspaces(py: Python<'_>) -> PyResult<PyObject> {
    let workspaces = with_framework(|framework| {
        let db = framework.db()?;
        db.workspaces()
    })?;
    json_to_py(py, &serde_json::json!(workspaces))
}

/// Get current workspace
#[pyfunction]
fn db_workspace(py: Python<'_>) -> PyResult<PyObject> {
    let workspace = with_framework(|framework| {
        let db = framework.db()?;
        db.workspace()
    })?;
    json_to_py(py, &workspace)
}

/// Set current workspace by name
#[pyfunction]
fn db_set_workspace(name: &str) -> PyResult<()> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.set_workspace(name)
    })?)
}

/// Create a new workspace
#[pyfunction]
fn db_add_workspace(py: Python<'_>, name: &str) -> PyResult<PyObject> {
    let workspace = with_framework(|framework| {
        let db = framework.db()?;
        db.add_workspace(name)
    })?;
    json_to_py(py, &workspace)
}

/// Find workspace by name
#[pyfunction]
fn db_find_workspace(py: Python<'_>, name: &str) -> PyResult<PyObject> {
    let workspace = with_framework(|framework| {
        let db = framework.db()?;
        db.find_workspace(name)
    })?;
    match workspace {
        Some(ws) => json_to_py(py, &ws),
        None => Ok(py.None()),
    }
}

/// Delete workspace by ID
#[pyfunction]
fn db_delete_workspace(workspace_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.delete_workspace(workspace_id)
    })?)
}

/// List notes in current workspace
#[pyfunction]
#[pyo3(signature = (options=None))]
fn db_notes(py: Python<'_>, options: Option<&Bound<'_, PyDict>>) -> PyResult<PyObject> {
    let opts = pydict_to_options(options)?;
    let notes = with_framework(|framework| {
        let db = framework.db()?;
        db.notes(opts)
    })?;
    json_to_py(py, &serde_json::json!(notes))
}

/// Report a note to the database
#[pyfunction]
fn db_report_note(options: &Bound<'_, PyDict>) -> PyResult<i64> {
    let opts = pydict_to_options(Some(options))?.unwrap_or_default();
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.report_note(opts)
    })?)
}

/// Delete notes by IDs
#[pyfunction]
fn db_delete_note(note_ids: Vec<i64>) -> PyResult<usize> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.delete_note(note_ids)
    })?)
}

// =============================================================================
// Database Query Functions (Tier 4.5B)
// =============================================================================

/// Get a single host by address
///
/// # Arguments
/// * `address` - IP address of the host to find
///
/// # Returns
/// Host info as dict or None if not found
#[pyfunction]
fn db_get_host(py: Python<'_>, address: &str) -> PyResult<PyObject> {
    let result = with_framework(|framework| {
        let db = framework.db()?;
        db.get_host(address)
    })?;

    match result {
        Some(json) => json_to_py(py, &json),
        None => Ok(py.None()),
    }
}

/// Get a single service by host and port
///
/// # Arguments
/// * `host` - IP address of the host
/// * `port` - Port number
/// * `proto` - Protocol (default: "tcp")
///
/// # Returns
/// Service info as dict or None if not found
#[pyfunction]
#[pyo3(signature = (host, port, proto=None))]
fn db_get_service(py: Python<'_>, host: &str, port: i32, proto: Option<&str>) -> PyResult<PyObject> {
    let result = with_framework(|framework| {
        let db = framework.db()?;
        db.get_service(host, port, proto)
    })?;

    match result {
        Some(json) => json_to_py(py, &json),
        None => Ok(py.None()),
    }
}

/// Get a single vulnerability by query options
///
/// # Arguments
/// * `options` - Query options dict (host, name, etc.)
///
/// # Returns
/// Vulnerability info as dict or None if not found
#[pyfunction]
fn db_get_vuln(py: Python<'_>, options: &Bound<'_, PyDict>) -> PyResult<PyObject> {
    let opts = pydict_to_options(Some(options))?.unwrap_or_default();
    let result = with_framework(|framework| {
        let db = framework.db()?;
        db.get_vuln(opts)
    })?;

    match result {
        Some(json) => json_to_py(py, &json),
        None => Ok(py.None()),
    }
}

/// Update a host by ID
///
/// # Arguments
/// * `host_id` - Host ID
/// * `options` - Fields to update (os_name, os_flavor, name, state)
///
/// # Returns
/// True if update succeeded
#[pyfunction]
fn db_update_host(host_id: i64, options: &Bound<'_, PyDict>) -> PyResult<bool> {
    let opts = pydict_to_options(Some(options))?.unwrap_or_default();
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.update_host(host_id, opts)
    })?)
}

/// Delete a host by ID
///
/// # Arguments
/// * `host_id` - Host ID to delete
///
/// # Returns
/// True if delete succeeded
#[pyfunction]
fn db_delete_host(host_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.delete_host(host_id)
    })?)
}

/// Update a service by ID
///
/// # Arguments
/// * `service_id` - Service ID
/// * `options` - Fields to update (name, state, info)
///
/// # Returns
/// True if update succeeded
#[pyfunction]
fn db_update_service(service_id: i64, options: &Bound<'_, PyDict>) -> PyResult<bool> {
    let opts = pydict_to_options(Some(options))?.unwrap_or_default();
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.update_service(service_id, opts)
    })?)
}

/// Delete a service by ID
///
/// # Arguments
/// * `service_id` - Service ID to delete
///
/// # Returns
/// True if delete succeeded
#[pyfunction]
fn db_delete_service(service_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let db = framework.db()?;
        db.delete_service(service_id)
    })?)
}

// =============================================================================
// Routing Functions (Tier 4)
// =============================================================================

/// Add a route through a session (for pivoting)
///
/// # Arguments
/// * `subnet` - The subnet to route (e.g., "10.10.10.0")
/// * `netmask` - The netmask (e.g., "255.255.255.0" or "24" for CIDR)
/// * `session_id` - The session ID to route traffic through
///
/// # Returns
/// `true` if the route was added, `false` if it already exists
#[pyfunction]
fn route_add(subnet: &str, netmask: &str, session_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        framework.route_add(subnet, netmask, session_id)
    })?)
}

/// Remove a route through a session
///
/// # Arguments
/// * `subnet` - The subnet to remove (e.g., "10.10.10.0")
/// * `netmask` - The netmask (e.g., "255.255.255.0")
/// * `session_id` - The session ID the route goes through
///
/// # Returns
/// `true` if the route was removed, `false` if it wasn't found
#[pyfunction]
fn route_remove(subnet: &str, netmask: &str, session_id: i64) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        framework.route_remove(subnet, netmask, session_id)
    })?)
}

/// List all routes in the routing table
///
/// # Returns
/// List of route dictionaries with subnet, netmask, session_id, comm_name
#[pyfunction]
fn route_list(py: Python<'_>) -> PyResult<PyObject> {
    let routes = with_framework(|framework| {
        framework.route_list()
    })?;
    json_to_py(py, &serde_json::json!(routes))
}

/// Flush all routes from the routing table
#[pyfunction]
fn route_flush() -> PyResult<()> {
    Ok(with_framework(|framework| {
        framework.route_flush()
    })?)
}

/// Check if a route exists
///
/// # Arguments
/// * `subnet` - The subnet to check
/// * `netmask` - The netmask
///
/// # Returns
/// `true` if the route exists
#[pyfunction]
fn route_exists(subnet: &str, netmask: &str) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        framework.route_exists(subnet, netmask)
    })?)
}

/// Find the best session for routing to an address
///
/// # Arguments
/// * `addr` - The IP address to route to
///
/// # Returns
/// The session ID if a route exists, None otherwise
#[pyfunction]
fn route_get(addr: &str) -> PyResult<Option<i64>> {
    Ok(with_framework(|framework| {
        framework.route_get(addr)
    })?)
}

// =============================================================================
// Python Module Definition
// =============================================================================

/// _rust - Python bindings for Metasploit Framework
///
/// This module provides Python access to MSF functionality through
/// an embedded Ruby VM. The Rust FFI layer is combined with Python
/// wrappers for a Pythonic API.
#[pymodule]
pub fn _rust(py: Python<'_>, module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    // Initialize pyo3-log to bridge Rust log messages to Python logging
    // This MUST be called first, before any log statements
    pyo3_log::init();

    module.add("__doc__", "Python interface to Metasploit Framework via Rust/Pyo3")?;
    module.add(
        "__all__",
        vec![
            "init_msf",
            "is_initialized",
            "framework_version",
            "module_stats",
            "add_module_path",
            "reload_modules",
            "list_modules",
            "list_sessions",
            "search",
            "get_session",
            "kill_session",
            "create_shell_session",
            "get_module_info",
            "create_module",
            "Module",
            "PySession",
            "exploit",
            "check",
            "AssassinateError",
            "poll_releasing_gvl",
            "sleep_releasing_gvl",
            "job_list",
            "job_info",
            "job_kill",
            "job_wait_for_session",
            // Payload generation (Tier 2)
            "forge_payload",
            "forge_encoded",
            "forge_executable",
            "list_payloads",
            "forge_payload_with_badchars",
            "forge_formatted",
            "transform_buffer",
            // Database (Tier 3)
            "db_active",
            "db_driver",
            "db_hosts",
            "db_services",
            "db_vulns",
            "db_creds",
            "db_loot",
            "db_report_host",
            "db_report_service",
            "db_report_vuln",
            "db_report_cred",
            "db_workspaces",
            "db_workspace",
            "db_set_workspace",
            "db_add_workspace",
            "db_find_workspace",
            "db_delete_workspace",
            "db_notes",
            "db_report_note",
            "db_delete_note",
            // Database query methods (Tier 4.5B)
            "db_get_host",
            "db_get_service",
            "db_get_vuln",
            "db_update_host",
            "db_delete_host",
            "db_update_service",
            "db_delete_service",
            // Routing (Tier 4)
            "route_add",
            "route_remove",
            "route_list",
            "route_flush",
            "route_exists",
            "route_get",
        ],
    )?;

    // Add exception
    module.add("AssassinateError", py.get_type_bound::<AssassinateError>())?;

    // Add functions
    module.add_function(wrap_pyfunction!(init_msf, module)?)?;
    module.add_function(wrap_pyfunction!(pyo3_is_initialized, module)?)?;
    module.add_function(wrap_pyfunction!(framework_version, module)?)?;
    module.add_function(wrap_pyfunction!(module_stats, module)?)?;
    module.add_function(wrap_pyfunction!(add_module_path, module)?)?;
    module.add_function(wrap_pyfunction!(reload_modules, module)?)?;
    module.add_function(wrap_pyfunction!(list_modules, module)?)?;
    module.add_function(wrap_pyfunction!(list_sessions, module)?)?;
    module.add_function(wrap_pyfunction!(search, module)?)?;
    module.add_function(wrap_pyfunction!(get_session, module)?)?;
    module.add_function(wrap_pyfunction!(kill_session, module)?)?;
    module.add_function(wrap_pyfunction!(create_shell_session, module)?)?;
    module.add_function(wrap_pyfunction!(get_module_info, module)?)?;
    module.add_function(wrap_pyfunction!(create_module, module)?)?;
    module.add_function(wrap_pyfunction!(exploit, module)?)?;
    module.add_function(wrap_pyfunction!(check, module)?)?;
    module.add_function(wrap_pyfunction!(poll_releasing_gvl, module)?)?;
    module.add_function(wrap_pyfunction!(sleep_releasing_gvl, module)?)?;
    module.add_function(wrap_pyfunction!(job_list, module)?)?;
    module.add_function(wrap_pyfunction!(job_info, module)?)?;
    module.add_function(wrap_pyfunction!(job_kill, module)?)?;
    module.add_function(wrap_pyfunction!(job_wait_for_session, module)?)?;

    // Payload generation (Tier 2)
    module.add_function(wrap_pyfunction!(forge_payload, module)?)?;
    module.add_function(wrap_pyfunction!(forge_encoded, module)?)?;
    module.add_function(wrap_pyfunction!(forge_executable, module)?)?;
    module.add_function(wrap_pyfunction!(list_payloads, module)?)?;
    module.add_function(wrap_pyfunction!(forge_payload_with_badchars, module)?)?;
    module.add_function(wrap_pyfunction!(forge_formatted, module)?)?;
    module.add_function(wrap_pyfunction!(transform_buffer, module)?)?;

    // Database (Tier 3)
    module.add_function(wrap_pyfunction!(db_active, module)?)?;
    module.add_function(wrap_pyfunction!(db_driver, module)?)?;
    module.add_function(wrap_pyfunction!(db_hosts, module)?)?;
    module.add_function(wrap_pyfunction!(db_services, module)?)?;
    module.add_function(wrap_pyfunction!(db_vulns, module)?)?;
    module.add_function(wrap_pyfunction!(db_creds, module)?)?;
    module.add_function(wrap_pyfunction!(db_loot, module)?)?;
    module.add_function(wrap_pyfunction!(db_report_host, module)?)?;
    module.add_function(wrap_pyfunction!(db_report_service, module)?)?;
    module.add_function(wrap_pyfunction!(db_report_vuln, module)?)?;
    module.add_function(wrap_pyfunction!(db_report_cred, module)?)?;
    module.add_function(wrap_pyfunction!(db_workspaces, module)?)?;
    module.add_function(wrap_pyfunction!(db_workspace, module)?)?;
    module.add_function(wrap_pyfunction!(db_set_workspace, module)?)?;
    module.add_function(wrap_pyfunction!(db_add_workspace, module)?)?;
    module.add_function(wrap_pyfunction!(db_find_workspace, module)?)?;
    module.add_function(wrap_pyfunction!(db_delete_workspace, module)?)?;
    module.add_function(wrap_pyfunction!(db_notes, module)?)?;
    module.add_function(wrap_pyfunction!(db_report_note, module)?)?;
    module.add_function(wrap_pyfunction!(db_delete_note, module)?)?;

    // Database query methods (Tier 4.5B)
    module.add_function(wrap_pyfunction!(db_get_host, module)?)?;
    module.add_function(wrap_pyfunction!(db_get_service, module)?)?;
    module.add_function(wrap_pyfunction!(db_get_vuln, module)?)?;
    module.add_function(wrap_pyfunction!(db_update_host, module)?)?;
    module.add_function(wrap_pyfunction!(db_delete_host, module)?)?;
    module.add_function(wrap_pyfunction!(db_update_service, module)?)?;
    module.add_function(wrap_pyfunction!(db_delete_service, module)?)?;

    // Routing (Tier 4)
    module.add_function(wrap_pyfunction!(route_add, module)?)?;
    module.add_function(wrap_pyfunction!(route_remove, module)?)?;
    module.add_function(wrap_pyfunction!(route_list, module)?)?;
    module.add_function(wrap_pyfunction!(route_flush, module)?)?;
    module.add_function(wrap_pyfunction!(route_exists, module)?)?;
    module.add_function(wrap_pyfunction!(route_get, module)?)?;

    // Add classes
    module.add_class::<MsfModule>()?;
    module.add_class::<PySession>()?;

    Ok(())
}
