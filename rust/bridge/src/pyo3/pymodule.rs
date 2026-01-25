//! Python module definition
//!
//! This module defines the `assassinate_pyo3` Python module with:
//! - `PySession` - Wrapper for MSF sessions (shell/meterpreter)
//! - `MsfModule` (exposed as `Module`) - Generic wrapper for all MSF module types
//!   (auxiliary, encoder, evasion, exploit, nop, payload, post)
//! - Module-level functions for framework operations

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
create_exception!(msf, AssassinateError, PyRuntimeError);

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

// Meterpreter Process
pyo3_wrap!(PySession, session, process_getpid() -> i64);
pyo3_wrap!(PySession, session, process_kill(pid: i64) -> ());
pyo3_wrap_json_vec!(PySession, session, process_list());

// Meterpreter System
pyo3_wrap!(PySession, session, sys_getuid() -> String);
pyo3_wrap!(PySession, session, sys_getsid() -> String);
pyo3_wrap!(PySession, session, sys_is_system() -> bool);
pyo3_wrap!(PySession, session, sys_localtime() -> String);
pyo3_wrap!(PySession, session, sys_getprivs() -> Vec<String>);
pyo3_wrap_json!(PySession, session, sys_sysinfo());
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

    /// Execute the exploit with the specified payload
    ///
    /// Returns the session ID if a session was created, None otherwise.
    fn exploit(&self, payload: &str) -> PyResult<Option<i64>> {
        Ok(self.module.exploit(payload, None)?)
    }

    /// Execute the exploit as a background job
    ///
    /// Returns the job ID if successful, None otherwise.
    fn exploit_job(&self, payload: &str) -> PyResult<Option<String>> {
        let mut options = Options::new();
        options.insert("RunAsJob".into(), RubyVal::Bool(true));

        let framework = self.module.framework()?;
        let jobs_before: Vec<String> = framework.jobs()?.list()?;

        let _ = self.module.exploit(payload, Some(options))?;

        let jobs_after: Vec<String> = framework.jobs()?.list()?;

        for job_id in jobs_after {
            if !jobs_before.contains(&job_id) {
                return Ok(Some(job_id));
            }
        }

        Ok(None)
    }

    /// Execute the exploit and wait for a session
    ///
    /// Polls for new sessions up to `timeout_secs` seconds.
    fn exploit_expect_session(
        &self,
        payload: &str,
        timeout_secs: u64,
    ) -> PyResult<Option<PySession>> {
        use std::thread;
        use std::time::Duration;

        let framework = self.module.framework()?;
        let session_manager = framework.sessions()?;
        let sessions_before = session_manager.list()?;

        let mut options = Options::new();
        options.insert("Quiet".into(), RubyVal::Bool(false));

        if let Some(sid) = self.module.exploit(payload, Some(options))? {
            if let Some(s) = session_manager.get(sid)? {
                return Ok(Some(PySession { session: s }));
            }
        }

        for _ in 0..timeout_secs {
            thread::sleep(Duration::from_secs(1));

            let sessions_now = session_manager.list()?;
            for sid in &sessions_now {
                if !sessions_before.contains(sid) {
                    if let Some(s) = session_manager.get(*sid)? {
                        return Ok(Some(PySession { session: s }));
                    }
                }
            }
        }

        Ok(None)
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

/// Sleep while releasing the Ruby GVL
///
/// Useful for allowing other Ruby threads to run during long operations.
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
#[pyfunction]
fn job_kill(job_id: &str) -> PyResult<bool> {
    Ok(with_framework(|framework| {
        let jobs = framework.jobs()?;
        jobs.kill(job_id)
    })?)
}

// =============================================================================
// Python Module Definition
// =============================================================================

/// msf - Python bindings for Metasploit Framework
///
/// This module provides Python access to MSF functionality through
/// an embedded Ruby VM. The Rust FFI layer is combined with Python
/// wrappers for a Pythonic API.
#[pymodule]
pub fn msf(py: Python<'_>, module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add("__doc__", "Python interface to Metasploit Framework via Rust/Pyo3")?;
    module.add(
        "__all__",
        vec![
            "init_msf",
            "is_initialized",
            "framework_version",
            "list_modules",
            "list_sessions",
            "search",
            "get_session",
            "kill_session",
            "get_module_info",
            "create_module",
            "Module",
            "PySession",
            "exploit",
            "check",
            "AssassinateError",
            "sleep_releasing_gvl",
            "job_list",
            "job_info",
            "job_kill",
        ],
    )?;

    // Add exception
    module.add("AssassinateError", py.get_type_bound::<AssassinateError>())?;

    // Add functions
    module.add_function(wrap_pyfunction!(init_msf, module)?)?;
    module.add_function(wrap_pyfunction!(pyo3_is_initialized, module)?)?;
    module.add_function(wrap_pyfunction!(framework_version, module)?)?;
    module.add_function(wrap_pyfunction!(list_modules, module)?)?;
    module.add_function(wrap_pyfunction!(list_sessions, module)?)?;
    module.add_function(wrap_pyfunction!(search, module)?)?;
    module.add_function(wrap_pyfunction!(get_session, module)?)?;
    module.add_function(wrap_pyfunction!(kill_session, module)?)?;
    module.add_function(wrap_pyfunction!(get_module_info, module)?)?;
    module.add_function(wrap_pyfunction!(create_module, module)?)?;
    module.add_function(wrap_pyfunction!(exploit, module)?)?;
    module.add_function(wrap_pyfunction!(check, module)?)?;
    module.add_function(wrap_pyfunction!(sleep_releasing_gvl, module)?)?;
    module.add_function(wrap_pyfunction!(job_list, module)?)?;
    module.add_function(wrap_pyfunction!(job_info, module)?)?;
    module.add_function(wrap_pyfunction!(job_kill, module)?)?;

    // Add classes
    module.add_class::<MsfModule>()?;
    module.add_class::<PySession>()?;

    Ok(())
}
