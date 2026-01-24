mod macros;

use std::cell::RefCell;

use bridge::error::AssassinateError as BridgeError;
use bridge::ruby_bootstrap::{ensure_ruby, init_ruby, require_all};
use bridge::ruby_bridge::{Options, RubyVal};
use bridge::{Framework, Module, Session};
use pyo3::create_exception;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use macros::{json_to_py, pyo3_wrap, pyo3_wrap_json, pyo3_wrap_json_vec, pyo3_wrap_hashmap, to_py_result};

create_exception!(assassinate_pyo3, AssassinateError, PyRuntimeError);

// Thread-local framework singleton
thread_local! {
    static FRAMEWORK: RefCell<Option<Framework>> = const { RefCell::new(None) };
}

fn with_framework<F, R>(f: F) -> PyResult<R>
where
    F: FnOnce(&Framework) -> PyResult<R>,
{
    FRAMEWORK.with(|cell| {
        let guard = cell.borrow();
        match guard.as_ref() {
            Some(framework) => f(framework),
            None => Err(AssassinateError::new_err(
                "Framework not initialized. Call init_msf() first.",
            )),
        }
    })
}

fn to_py_err(err: BridgeError) -> PyErr {
    AssassinateError::new_err(err.to_string())
}

// =============================================================================
// PySession - Wrapper for MSF Session
// =============================================================================

#[pyclass(unsendable)]
struct PySession {
    session: Session,
}

// Generate wrapper methods via macros (each generates a separate #[pymethods] impl block)
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
    fn run_cmd(&self, cmd: &str, timeout: Option<u32>) -> PyResult<String> {
        to_py_result(self.session.run_cmd(cmd, timeout))
    }

    fn read(&self, length: Option<usize>) -> PyResult<String> {
        to_py_result(self.session.read(length))
    }

    fn write(&self, data: &str) -> PyResult<usize> {
        to_py_result(self.session.write(data))
    }

    fn sid(&self) -> i64 {
        self.session.session_id
    }

    fn shell_to_meterpreter(&self, lhost: &str, lport: u16) -> PyResult<bool> {
        to_py_result(self.session.shell_to_meterpreter(lhost, lport, None))
    }

    fn process_execute(
        &self,
        py: Python<'_>,
        path: &str,
        args: &str,
        hidden: Option<bool>,
        channelized: Option<bool>,
    ) -> PyResult<PyObject> {
        let value = to_py_result(self.session.process_execute(
            path,
            args,
            hidden.unwrap_or(false),
            channelized.unwrap_or(false),
        ))?;
        json_to_py(py, &value)
    }

    fn sys_getenv(&self, var_name: &str) -> PyResult<Option<String>> {
        to_py_result(self.session.sys_getenv(var_name))
    }

    fn sys_getenvs(&self, py: Python<'_>, var_names: Vec<String>) -> PyResult<PyObject> {
        let map = to_py_result(self.session.sys_getenvs(var_names))?;
        let dict = PyDict::new_bound(py);
        for (k, v) in map {
            dict.set_item(k, v)?;
        }
        Ok(dict.into())
    }

    fn meterpreter_machine_id(&self, timeout: Option<u32>) -> PyResult<String> {
        to_py_result(self.session.meterpreter_machine_id(timeout))
    }

    fn meterpreter_native_arch(&self, timeout: Option<u32>) -> PyResult<String> {
        to_py_result(self.session.meterpreter_native_arch(timeout))
    }

    fn meterpreter_session_guid(&self, timeout: Option<u32>) -> PyResult<String> {
        to_py_result(self.session.meterpreter_session_guid(timeout))
    }

    fn meterpreter_migrate(
        &self,
        target_pid: i64,
        writable_dir: Option<&str>,
        timeout: Option<u32>,
    ) -> PyResult<bool> {
        to_py_result(self.session.meterpreter_migrate(target_pid, writable_dir, timeout))
    }

    fn set_transport_timeouts(
        &self,
        py: Python<'_>,
        session_exp: Option<i64>,
        comm_timeout: Option<i64>,
        retry_total: Option<i64>,
        retry_wait: Option<i64>,
    ) -> PyResult<PyObject> {
        let value = to_py_result(
            self.session
                .set_transport_timeouts(session_exp, comm_timeout, retry_total, retry_wait),
        )?;
        json_to_py(py, &value)
    }

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
        to_py_result(self.session.transport_add(
            transport,
            lhost,
            lport,
            ua,
            comm_timeout,
            session_exp,
            retry_total,
            retry_wait,
        ))
    }

    #[pyo3(signature = (transport, lport, lhost=None))]
    fn transport_remove(&self, transport: &str, lport: u16, lhost: Option<&str>) -> PyResult<bool> {
        to_py_result(self.session.transport_remove(transport, lhost, lport))
    }

    #[pyo3(signature = (transport, lport, lhost=None))]
    fn transport_change(&self, transport: &str, lport: u16, lhost: Option<&str>) -> PyResult<bool> {
        to_py_result(self.session.transport_change(transport, lhost, lport))
    }

    fn run_post_module(&self, module_path: &str, options: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
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
        to_py_result(self.session.run_post_module(module_path, opts))
    }
}

// =============================================================================
// ExploitModule - Wrapper for MSF Module
// =============================================================================

#[pyclass(unsendable)]
struct ExploitModule {
    module: Module,
    fullname: String,
}

// Generate wrapper methods via macros
// Module Metadata
pyo3_wrap!(ExploitModule, module, description() -> String);
pyo3_wrap!(ExploitModule, module, author() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, references() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, platform() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, arch() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, rank() -> String);
pyo3_wrap!(ExploitModule, module, license() -> String);
pyo3_wrap!(ExploitModule, module, disclosure_date() -> Option<String>);
pyo3_wrap!(ExploitModule, module, privileged() -> bool);
pyo3_wrap!(ExploitModule, module, targets() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, aliases() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, action() -> Option<String>);
pyo3_wrap_hashmap!(ExploitModule, module, notes());

// Options
pyo3_wrap!(ExploitModule, module, set_option(key: &str, value: &str) -> ());
pyo3_wrap!(ExploitModule, module, missing_required() -> Vec<String>);

// Validation
pyo3_wrap!(ExploitModule, module, validate() -> bool);
pyo3_wrap!(ExploitModule, module, has_check() -> bool);
pyo3_wrap!(ExploitModule, module, check() -> String);

// Compatibility
pyo3_wrap!(ExploitModule, module, compatible_payloads() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, actions() -> Vec<String>);
pyo3_wrap!(ExploitModule, module, default_action() -> Option<String>);

// Manual implementations for complex methods
#[pymethods]
impl ExploitModule {
    fn exploit(&self, payload: &str) -> PyResult<Option<i64>> {
        to_py_result(self.module.exploit(payload, None))
    }

    fn exploit_job(&self, payload: &str) -> PyResult<Option<String>> {
        let mut options = Options::new();
        options.insert("RunAsJob".into(), RubyVal::Bool(true));

        let framework = to_py_result(self.module.framework())?;
        let jobs_before: Vec<String> = to_py_result(to_py_result(framework.jobs())?.list())?;

        let _ = to_py_result(self.module.exploit(payload, Some(options)))?;

        let jobs_after: Vec<String> = to_py_result(to_py_result(framework.jobs())?.list())?;

        for job_id in jobs_after {
            if !jobs_before.contains(&job_id) {
                return Ok(Some(job_id));
            }
        }

        Ok(None)
    }

    fn exploit_expect_session(&self, payload: &str, timeout_secs: u64) -> PyResult<Option<PySession>> {
        use std::thread;
        use std::time::Duration;

        let framework = to_py_result(self.module.framework())?;
        let session_manager = to_py_result(framework.sessions())?;
        let sessions_before = to_py_result(session_manager.list())?;

        let mut options = Options::new();
        options.insert("Quiet".into(), RubyVal::Bool(false));

        if let Some(sid) = to_py_result(self.module.exploit(payload, Some(options)))? {
            if let Some(s) = to_py_result(session_manager.get(sid))? {
                return Ok(Some(PySession { session: s }));
            }
        }

        for _ in 0..timeout_secs {
            thread::sleep(Duration::from_secs(1));

            let sessions_now = to_py_result(session_manager.list())?;
            for sid in &sessions_now {
                if !sessions_before.contains(sid) {
                    if let Some(s) = to_py_result(session_manager.get(*sid))? {
                        return Ok(Some(PySession { session: s }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn run(&self) -> PyResult<bool> {
        to_py_result(self.module.run(None))
    }

    fn fullname(&self) -> String {
        self.fullname.clone()
    }

    fn _options_structured(&self, py: Python<'_>) -> PyResult<PyObject> {
        let opts = to_py_result(self.module.options_structured())?;
        let dict = PyDict::new_bound(py);
        for (key, value) in opts {
            let py_value = json_to_py(py, &value)?;
            dict.set_item(key, py_value)?;
        }
        Ok(dict.into())
    }

    fn _get_option(&self, key: &str) -> PyResult<Option<String>> {
        to_py_result(self.module.get_option(key))
    }

    fn _set_option(&self, key: &str, value: &str) -> PyResult<()> {
        to_py_result(self.module.set_option(key, value))
    }

    fn _missing_required(&self) -> PyResult<Vec<String>> {
        to_py_result(self.module.missing_required())
    }
}

// =============================================================================
// Module Functions
// =============================================================================

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

#[pyfunction]
fn init_msf(msf_root: &str) -> PyResult<()> {
    to_py_result(init_msf_generic(msf_root))?;

    FRAMEWORK.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            let framework = Framework::new(None)
                .expect("Failed to create Framework after successful init_msf_generic");
            *guard = Some(framework);
        }
    });

    Ok(())
}

#[pyfunction]
fn is_initialized() -> bool {
    FRAMEWORK.with(|cell| cell.borrow().is_some())
}

#[pyfunction]
fn framework_version() -> PyResult<String> {
    with_framework(|framework| to_py_result(framework.version()))
}

#[pyfunction]
fn list_modules(module_type: &str) -> PyResult<Vec<String>> {
    with_framework(|framework| to_py_result(framework.list_modules(module_type)))
}

#[pyfunction]
fn get_module_info(module_name: &str, py: Python<'_>) -> PyResult<PyObject> {
    with_framework(|framework| {
        let module = to_py_result(framework.create_module(module_name))?;

        let info = PyDict::new_bound(py);

        let fullname = module.fullname().map_err(to_py_err)?;
        info.set_item("fullname", &fullname)?;

        let description = module.description().map_err(to_py_err)?;
        let desc_str = if description.is_empty() { "N/A" } else { &description };
        info.set_item("description", desc_str)?;

        let mtype = module.module_type().map_err(to_py_err)?;
        info.set_item("module_type", mtype)?;

        info.set_item("name", fullname.split('/').last().unwrap_or(""))?;

        Ok(info.into())
    })
}

#[pyfunction]
fn create_module(module_name: &str) -> PyResult<ExploitModule> {
    with_framework(|framework| {
        let module = to_py_result(framework.create_module(module_name))?;
        let fullname = to_py_result(module.fullname())?;
        Ok(ExploitModule { module, fullname })
    })
}

#[pyfunction]
fn exploit(module_fullname: &str, payload: &str) -> PyResult<Option<i64>> {
    with_framework(|framework| {
        let module = to_py_result(framework.create_module(module_fullname))?;
        to_py_result(module.exploit(payload, None))
    })
}

#[pyfunction]
fn check(module_fullname: &str) -> PyResult<String> {
    with_framework(|framework| {
        let module = to_py_result(framework.create_module(module_fullname))?;
        to_py_result(module.check())
    })
}

#[pyfunction]
fn list_sessions() -> PyResult<Vec<i64>> {
    with_framework(|framework| {
        let session_manager = to_py_result(framework.sessions())?;
        to_py_result(session_manager.list())
    })
}

#[pyfunction]
fn search(query: &str) -> PyResult<Vec<String>> {
    with_framework(|framework| to_py_result(framework.search(query)))
}

#[pyfunction]
fn get_session(session_id: i64) -> PyResult<Option<PySession>> {
    with_framework(|framework| {
        let session_manager = to_py_result(framework.sessions())?;
        match to_py_result(session_manager.get(session_id))? {
            Some(session) => Ok(Some(PySession { session })),
            None => Ok(None),
        }
    })
}

#[pyfunction]
fn kill_session(session_id: i64) -> PyResult<bool> {
    with_framework(|framework| {
        let session_manager = to_py_result(framework.sessions())?;
        to_py_result(session_manager.kill(session_id))
    })
}

#[pyfunction]
fn sleep_releasing_gvl(duration_ms: u64) {
    bridge::gvl::sleep_releasing_gvl(duration_ms);
}

#[pyfunction]
fn job_list() -> PyResult<Vec<String>> {
    with_framework(|framework| {
        let jobs = to_py_result(framework.jobs())?;
        to_py_result(jobs.list())
    })
}

#[pyfunction]
fn job_info(job_id: &str) -> PyResult<Option<String>> {
    with_framework(|framework| {
        let jobs = to_py_result(framework.jobs())?;
        to_py_result(jobs.get(job_id))
    })
}

#[pyfunction]
fn job_kill(job_id: &str) -> PyResult<bool> {
    with_framework(|framework| {
        let jobs = to_py_result(framework.jobs())?;
        to_py_result(jobs.kill(job_id))
    })
}

#[pymodule]
fn assassinate_pyo3(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__doc__", "Pyo3/Magnus POC for MSF exploit chain workflow")?;
    module.add("__all__", vec![
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
        "ExploitModule",
        "PySession",
        "exploit",
        "check",
        "AssassinateError",
        "sleep_releasing_gvl",
        "job_list",
        "job_info",
        "job_kill",
    ])?;
    module.add("AssassinateError", py.get_type_bound::<AssassinateError>())?;
    module.add_function(wrap_pyfunction!(init_msf, module)?)?;
    module.add_function(wrap_pyfunction!(is_initialized, module)?)?;
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
    module.add_class::<ExploitModule>()?;
    module.add_class::<PySession>()?;
    Ok(())
}
