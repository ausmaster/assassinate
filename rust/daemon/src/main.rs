use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bridge::{Framework, Module};
use clap::Parser;
use futures::stream::StreamExt;
use ipc::{protocol, IpcError, RingBuffer, DEFAULT_BUFFER_SIZE, DEFAULT_SHM_NAME};
use parking_lot::Mutex;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Cleanup guard that ensures shared memory is removed even on panic or unexpected exit
struct CleanupGuard {
    shm_name: String,
}

impl CleanupGuard {
    fn new(shm_name: String) -> Self {
        Self { shm_name }
    }

    fn cleanup(&self) {
        let request_shm_path = format!("/dev/shm/{}_req", self.shm_name);
        let response_shm_path = format!("/dev/shm/{}_resp", self.shm_name);

        // Try to remove both, don't care if they fail
        let _ = std::fs::remove_file(&request_shm_path);
        let _ = std::fs::remove_file(&response_shm_path);
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        info!("Cleaning up shared memory segments...");
        self.cleanup();
    }
}

/// Assassinate Daemon - High-performance IPC bridge to Metasploit Framework
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to Metasploit Framework installation
    #[arg(short, long)]
    msf_root: Option<PathBuf>,

    /// Shared memory name for IPC
    #[arg(short, long, default_value = DEFAULT_SHM_NAME)]
    shm_name: String,

    /// Ring buffer size in bytes (must be power of 2)
    #[arg(short, long, default_value_t = DEFAULT_BUFFER_SIZE)]
    buffer_size: usize,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

/// Main daemon structure
struct Daemon {
    framework: Framework,
    request_buffer: RingBuffer,  // Python writes, Daemon reads
    response_buffer: RingBuffer, // Daemon writes, Python reads
    shutdown: Arc<AtomicBool>,
    request_count: AtomicU64,
    error_count: AtomicU64,
    // Module instance storage
    modules: Arc<Mutex<HashMap<String, Module>>>,
    next_module_id: AtomicU64,
}

/// Helper function to parse options from JSON Value to HashMap
fn parse_options(value: Option<&serde_json::Value>) -> Option<HashMap<String, String>> {
    value.and_then(|v| v.as_object()).map(|obj| {
        obj.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    })
}

/// Helper function to get a required string argument from args
fn get_str_arg<'a>(args: &'a [serde_json::Value], index: usize, name: &str) -> Result<&'a str> {
    args.get(index)
        .and_then(|v| v.as_str())
        .context(format!("Missing {}", name))
}

impl Daemon {
    /// Create a new daemon instance
    fn new(
        framework: Framework,
        request_buffer: RingBuffer,
        response_buffer: RingBuffer,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            framework,
            request_buffer,
            response_buffer,
            shutdown,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            modules: Arc::new(Mutex::new(HashMap::new())),
            next_module_id: AtomicU64::new(1),
        }
    }

    // ========== DRY Helper Methods ==========

    /// Execute a closure with a session, handling the common lookup pattern.
    /// Extracts session_id from args[0], looks up the session, and calls the closure.
    fn with_session<F, T>(&self, args: &[serde_json::Value], f: F) -> Result<T>
    where
        F: FnOnce(bridge::Session) -> Result<T>,
    {
        let session_id = args
            .get(0)
            .and_then(|v| v.as_i64())
            .context("Missing session_id")?;
        let sessions = self.framework.sessions()?;
        if let Some(sess_val) = sessions.get_raw(session_id)? {
            let session = bridge::Session::from_raw(sess_val, session_id);
            f(session)
        } else {
            bail!("Session not found")
        }
    }

    /// Execute a closure with a session, returning null JSON for missing sessions.
    /// Used for queries where missing session returns null instead of error.
    fn with_session_or_null<F>(&self, args: &[serde_json::Value], f: F) -> Result<serde_json::Value>
    where
        F: FnOnce(bridge::Session) -> Result<serde_json::Value>,
    {
        let session_id = args
            .get(0)
            .and_then(|v| v.as_i64())
            .context("Missing session_id")?;
        let sessions = self.framework.sessions()?;
        if let Some(sess_val) = sessions.get_raw(session_id)? {
            let session = bridge::Session::from_raw(sess_val, session_id);
            f(session)
        } else {
            Ok(serde_json::json!({ "session": null }))
        }
    }

    /// Main event loop - processes IPC requests
    async fn run(&self) -> Result<()> {
        info!("Daemon started - waiting for requests");
        let mut last_stats_log = Instant::now();
        let stats_interval = Duration::from_secs(60);

        // Adaptive backoff for efficient polling
        let mut backoff_micros = 1u64;
        const MIN_BACKOFF_MICROS: u64 = 1;
        const MAX_BACKOFF_MICROS: u64 = 100;

        while !self.shutdown.load(Ordering::Relaxed) {
            match self.request_buffer.try_read() {
                Ok(data) => {
                    // Reset backoff on successful read
                    backoff_micros = MIN_BACKOFF_MICROS;
                    self.request_count.fetch_add(1, Ordering::Relaxed);

                    match self.process_request(data).await {
                        Ok(()) => {}
                        Err(e) => {
                            self.error_count.fetch_add(1, Ordering::Relaxed);
                            error!("Failed to process request: {:#}", e);
                        }
                    }
                }
                Err(IpcError::RingBufferEmpty) => {
                    // No data available - use adaptive backoff
                    tokio::task::yield_now().await;
                    sleep(Duration::from_micros(backoff_micros)).await;

                    // Exponential backoff: double the wait time up to maximum
                    backoff_micros = (backoff_micros * 2).min(MAX_BACKOFF_MICROS);
                }
                Err(e) => {
                    self.error_count.fetch_add(1, Ordering::Relaxed);
                    error!("Ring buffer read error: {:#}", e);
                    sleep(Duration::from_millis(10)).await;
                }
            }

            // Periodically log statistics
            if last_stats_log.elapsed() >= stats_interval {
                self.log_statistics();
                last_stats_log = Instant::now();
            }
        }

        info!("Daemon shutting down gracefully");
        Ok(())
    }

    /// Process a single IPC request
    async fn process_request(&self, data: &[u8]) -> Result<()> {
        let start = Instant::now();
        let request_size = data.len();

        // Deserialize request
        let (call_id, method, args) =
            protocol::deserialize_call(data).context("Failed to deserialize request")?;

        let num_args = args.len();
        debug!(
            call_id = call_id,
            method = %method,
            num_args = num_args,
            request_size = request_size,
            "Processing RPC call"
        );

        // Dispatch and measure
        let dispatch_start = Instant::now();
        let response = match self.dispatch_call(&method, args).await {
            Ok(result) => {
                let dispatch_time = dispatch_start.elapsed();
                debug!(
                    call_id = call_id,
                    method = %method,
                    dispatch_ms = dispatch_time.as_millis(),
                    "RPC call succeeded"
                );
                protocol::serialize_response(call_id, result)?
            }
            Err(e) => {
                let dispatch_time = dispatch_start.elapsed();
                let error_msg = format!("{:#}", e);
                warn!(
                    call_id = call_id,
                    method = %method,
                    error = %error_msg,
                    dispatch_ms = dispatch_time.as_millis(),
                    "RPC call failed"
                );
                protocol::serialize_error(call_id, "CallFailed", &error_msg)?
            }
        };

        let response_size = response.len();

        // Send response
        self.response_buffer
            .try_write(&response)
            .context("Failed to write response to ring buffer")?;

        let total_time = start.elapsed();
        debug!(
            call_id = call_id,
            method = %method,
            total_ms = total_time.as_millis(),
            response_size = response_size,
            "Request completed"
        );

        Ok(())
    }

    /// Dispatch method call to MSF framework
    async fn dispatch_call(
        &self,
        method: &str,
        _args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        match method {
            // === Framework Core Methods ===
            "framework_version" => {
                let version = self
                    .framework
                    .version()
                    .context("Failed to get framework version")?;
                Ok(serde_json::json!({ "version": version }))
            }

            "list_modules" => {
                let module_type = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid module_type argument")?;

                let modules = self
                    .framework
                    .list_modules(module_type)
                    .context("Failed to list modules")?;

                Ok(serde_json::json!({ "modules": modules }))
            }

            // === Module Search and Discovery ===
            "search" => {
                let query = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid search query")?;

                let results = self
                    .framework
                    .search(query)
                    .context("Failed to search modules")?;

                Ok(serde_json::json!({ "results": results }))
            }

            "get_module_info" => {
                let module_name = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid module_name argument")?;

                let module = self
                    .framework
                    .create_module(module_name)
                    .context("Failed to create module")?;

                Ok(serde_json::json!({
                    "name": module.name()?,
                    "fullname": module.fullname()?,
                    "type": module.module_type()?,
                    "rank": module.rank()?,
                    "disclosure_date": module.disclosure_date()?,
                    "description": module.description()?,
                }))
            }

            "threads" => {
                let threads = self
                    .framework
                    .threads()
                    .context("Failed to get thread count")?;
                Ok(serde_json::json!({ "threads": threads }))
            }

            // === Session Listing ===
            "list_sessions" => {
                let session_manager = self
                    .framework
                    .sessions()
                    .context("Failed to get session manager")?;

                let session_ids = session_manager.list().context("Failed to list sessions")?;

                Ok(serde_json::json!({ "session_ids": session_ids }))
            }

            // === Module Instance Management ===
            "create_module" => {
                let module_path = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid module_path argument")?;

                // Create the module
                let module = self
                    .framework
                    .create_module(module_path)
                    .context("Failed to create module")?;

                // Generate unique ID and store module
                let module_id = self
                    .next_module_id
                    .fetch_add(1, Ordering::SeqCst)
                    .to_string();
                self.modules.lock().insert(module_id.clone(), module);

                Ok(serde_json::json!({ "module_id": module_id }))
            }

            // === Module Information and Options ===
            "module_info" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing or invalid module_id argument")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;

                Ok(serde_json::json!({
                    "name": module.name()?,
                    "fullname": module.fullname()?,
                    "type": module.module_type()?,
                    "description": module.description()?,
                    "rank": module.rank()?,
                    "disclosure_date": module.disclosure_date().ok(),
                    "author": module.author().ok(),
                    "references": module.references().ok(),
                    "platform": module.platform().ok(),
                    "arch": module.arch().ok(),
                    "privileged": module.privileged().ok(),
                    "license": module.license().ok(),
                }))
            }

            "module_set_option" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let key = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;
                let value = _args
                    .get(2)
                    .and_then(|v| v.as_str())
                    .context("Missing value")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let datastore = module.datastore()?;
                datastore.set(key, value)?;

                Ok(serde_json::json!({}))
            }

            "module_get_option" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let key = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let datastore = module.datastore()?;
                let value = datastore.get(key)?;

                Ok(serde_json::json!({ "value": value }))
            }

            "module_validate" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let valid = module.validate()?;

                Ok(serde_json::json!({ "valid": valid }))
            }

            "module_compatible_payloads" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let payloads = module.compatible_payloads()?;

                Ok(serde_json::json!({ "payloads": payloads }))
            }

            "module_actions" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let actions = module.actions()?;

                Ok(serde_json::json!({ "actions": actions }))
            }

            "module_default_action" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let default_action = module.default_action()?;

                Ok(serde_json::json!({ "default_action": default_action }))
            }

            "module_action" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let action = module.action()?;

                Ok(serde_json::json!({ "action": action }))
            }

            "module_has_check" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let has_check = module.has_check()?;

                Ok(serde_json::json!({ "has_check": has_check }))
            }

            "module_check" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let check_result = module.check()?;

                Ok(serde_json::json!({ "check_result": check_result }))
            }

            "module_options" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let options = module.options()?;

                Ok(serde_json::json!({ "options": options }))
            }

            "module_targets" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let targets = module.targets()?;

                Ok(serde_json::json!({ "targets": targets }))
            }

            "module_aliases" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let aliases = module.aliases()?;

                Ok(serde_json::json!({ "aliases": aliases }))
            }

            "module_notes" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let notes = module.notes()?;

                Ok(serde_json::json!({ "notes": notes }))
            }

            // === Framework-level DataStore Operations ===
            "framework_get_option" => {
                let key = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;
                let datastore = self.framework.datastore()?;
                let value = datastore.get(key)?;
                Ok(serde_json::json!({ "value": value }))
            }

            "framework_set_option" => {
                let key = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;
                let value = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing value")?;
                let datastore = self.framework.datastore()?;
                datastore.set(key, value)?;
                Ok(serde_json::json!({}))
            }

            "framework_datastore_to_dict" => {
                let datastore = self.framework.datastore()?;
                let dict = datastore.to_dict()?;
                Ok(serde_json::json!({ "datastore": dict }))
            }

            "framework_delete_option" => {
                let key = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;
                let datastore = self.framework.datastore()?;
                datastore.delete(key)?;
                Ok(serde_json::json!({}))
            }

            "framework_clear_datastore" => {
                let datastore = self.framework.datastore()?;
                datastore.clear()?;
                Ok(serde_json::json!({}))
            }

            // === Module-level DataStore Operations ===
            "module_datastore_to_dict" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let datastore = module.datastore()?;
                let dict = datastore.to_dict()?;
                Ok(serde_json::json!({ "datastore": dict }))
            }

            "module_delete_option" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let key = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing key")?;
                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let datastore = module.datastore()?;
                datastore.delete(key)?;
                Ok(serde_json::json!({}))
            }

            "module_clear_datastore" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let datastore = module.datastore()?;
                datastore.clear()?;
                Ok(serde_json::json!({}))
            }

            // === PayloadGenerator Operations ===
            "payload_generate" => {
                let payload_name = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing payload_name")?;
                let options = parse_options(_args.get(1));

                let pg = bridge::PayloadGenerator::new(&self.framework)?;
                let payload_bytes = pg.generate(payload_name, options)?;
                let payload_b64 = BASE64.encode(&payload_bytes);

                Ok(serde_json::json!({ "payload": payload_b64 }))
            }

            "payload_generate_encoded" => {
                let payload_name = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing payload_name")?;
                let encoder = _args.get(1).and_then(|v| v.as_str());
                let iterations = _args.get(2).and_then(|v| v.as_i64()).map(|i| i as i32);
                let options = parse_options(_args.get(3));

                let pg = bridge::PayloadGenerator::new(&self.framework)?;
                let payload_bytes =
                    pg.generate_encoded(payload_name, encoder, iterations, options)?;
                let payload_b64 = BASE64.encode(&payload_bytes);

                Ok(serde_json::json!({ "payload": payload_b64 }))
            }

            "payload_list_payloads" => {
                let pg = bridge::PayloadGenerator::new(&self.framework)?;
                let payloads = pg.list_payloads()?;
                Ok(serde_json::json!({ "payloads": payloads }))
            }

            "payload_generate_executable" => {
                let payload_name = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing payload_name")?;
                let platform = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing platform")?;
                let arch = _args
                    .get(2)
                    .and_then(|v| v.as_str())
                    .context("Missing arch")?;
                let options = parse_options(_args.get(3));

                let pg = bridge::PayloadGenerator::new(&self.framework)?;
                let exe_bytes = pg.generate_executable(payload_name, platform, arch, options)?;
                let exe_b64 = BASE64.encode(&exe_bytes);

                Ok(serde_json::json!({ "executable": exe_b64 }))
            }

            // === Database Manager Operations ===
            "db_hosts" => {
                let db = self.framework.db()?;
                let hosts = db.hosts()?;
                Ok(serde_json::json!({ "hosts": hosts }))
            }

            "db_services" => {
                let db = self.framework.db()?;
                let services = db.services()?;
                Ok(serde_json::json!({ "services": services }))
            }

            "db_report_host" => {
                let db = self.framework.db()?;
                let host_id = db.report_host(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "host_id": host_id }))
            }

            "db_report_service" => {
                let db = self.framework.db()?;
                let service_id = db.report_service(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "service_id": service_id }))
            }

            "db_report_vuln" => {
                let db = self.framework.db()?;
                let vuln_id = db.report_vuln(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "vuln_id": vuln_id }))
            }

            "db_report_cred" => {
                let db = self.framework.db()?;
                let cred_id = db.report_cred(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "cred_id": cred_id }))
            }

            "db_vulns" => {
                let db = self.framework.db()?;
                let vulns = db.vulns()?;
                Ok(serde_json::json!({ "vulns": vulns }))
            }

            "db_creds" => {
                let db = self.framework.db()?;
                let creds = db.creds()?;
                Ok(serde_json::json!({ "creds": creds }))
            }

            "db_loot" => {
                let db = self.framework.db()?;
                let loot = db.loot()?;
                Ok(serde_json::json!({ "loot": loot }))
            }

            // === Job Manager Operations ===
            "job_list" => {
                let jobs = self.framework.jobs()?;
                let job_ids = jobs.list()?;
                Ok(serde_json::json!({ "job_ids": job_ids }))
            }

            "job_get" => {
                let job_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing job_id")?;
                let jobs = self.framework.jobs()?;
                let job_info = jobs.get_raw(job_id)?;
                Ok(serde_json::json!({ "job_info": job_info }))
            }

            "job_kill" => {
                let job_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing job_id")?;
                let jobs = self.framework.jobs()?;
                let success = jobs.kill_raw(job_id)?;
                Ok(serde_json::json!({ "success": success }))
            }

            // === Plugin Manager Operations ===
            "plugins_list" => {
                let plugins = self.framework.plugins()?;
                let plugin_names = plugins.list_raw()?;
                Ok(serde_json::json!({ "plugins": plugin_names }))
            }

            "plugins_load" => {
                let path = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing path")?;
                let options = parse_options(_args.get(1));

                let plugins = self.framework.plugins()?;
                let plugin_name = plugins.load_raw(path, options)?;
                Ok(serde_json::json!({ "plugin_name": plugin_name }))
            }

            "plugins_unload" => {
                let plugin_name = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing plugin_name")?;
                let plugins = self.framework.plugins()?;
                let success = plugins.unload_raw(plugin_name)?;
                Ok(serde_json::json!({ "success": success }))
            }

            // === Session Manager Operations ===
            "session_get" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                let session_val = sessions.get_raw(session_id)?;

                if let Some(sess_val) = session_val {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    // Return session metadata
                    Ok(serde_json::json!({
                        "session_id": session_id,
                        "type": session.session_type()?,
                        "info": session.info()?,
                        "desc": session.desc()?,
                        "alive": session.alive()?,
                    }))
                } else {
                    Ok(serde_json::json!({ "session": null }))
                }
            }

            "session_kill" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                let success = sessions.kill_raw(session_id)?;
                Ok(serde_json::json!({ "success": success }))
            }

            "session_info" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "info": session.info()? }))
            }),

            "session_type" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "type": session.session_type()? }))
            }),

            "session_alive" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "alive": session.alive()? }))
            }),

            "session_read" => {
                let length = _args.get(1).and_then(|v| v.as_u64()).map(|v| v as usize);
                self.with_session(&_args, |session| {
                    let data = session.read_raw(length)?;
                    Ok(serde_json::json!({ "data": data }))
                })
            }

            "session_write" => {
                let data = get_str_arg(&_args, 1, "data")?;
                self.with_session(&_args, |session| {
                    let bytes_written = session.write_raw(data)?;
                    Ok(serde_json::json!({ "bytes_written": bytes_written }))
                })
            }

            "session_execute" => {
                let command = get_str_arg(&_args, 1, "command")?;
                self.with_session(&_args, |session| {
                    let output = session.execute_raw(command)?;
                    Ok(serde_json::json!({ "output": output }))
                })
            }

            "session_run_cmd" => {
                let command = get_str_arg(&_args, 1, "command")?;
                self.with_session(&_args, |session| {
                    let output = session.run_cmd_raw(command)?;
                    Ok(serde_json::json!({ "output": output }))
                })
            }

            "session_desc" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "desc": session.desc()? }))
            }),

            "session_host" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "host": session.session_host()? }))
            }),

            "session_port" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "port": session.session_port()? }))
            }),

            "session_tunnel_peer" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "tunnel_peer": session.tunnel_peer()? }))
            }),

            "session_target_host" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "target_host": session.target_host()? }))
            }),

            "session_via_exploit" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "via_exploit": session.via_exploit()? }))
            }),

            "session_via_payload" => self.with_session_or_null(&_args, |session| {
                Ok(serde_json::json!({ "via_payload": session.via_payload()? }))
            }),

            // === Session Filesystem Operations (Meterpreter) ===
            "session_fs_pwd" => self.with_session(&_args, |session| {
                Ok(serde_json::json!({ "pwd": session.fs_pwd()? }))
            }),

            "session_fs_chdir" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    session.fs_chdir(path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_ls" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "entries": session.fs_ls(path)? }))
                })
            }

            "session_fs_mkdir" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    session.fs_mkdir(path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_rmdir" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    session.fs_rmdir(path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_stat" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "stat": session.fs_stat(path)? }))
                })
            }

            "session_fs_exists" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "exists": session.fs_exists(path)? }))
                })
            }

            "session_fs_rm" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    session.fs_rm(path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_mv" => {
                let old_path = get_str_arg(&_args, 1, "old_path")?;
                let new_path = get_str_arg(&_args, 2, "new_path")?;
                self.with_session(&_args, |session| {
                    session.fs_mv(old_path, new_path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_cp" => {
                let src_path = get_str_arg(&_args, 1, "src_path")?;
                let dst_path = get_str_arg(&_args, 2, "dst_path")?;
                self.with_session(&_args, |session| {
                    session.fs_cp(src_path, dst_path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_fs_separator" => self.with_session(&_args, |session| {
                Ok(serde_json::json!({ "separator": session.fs_separator()? }))
            }),

            "session_fs_expand_path" => {
                let path = get_str_arg(&_args, 1, "path")?;
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "expanded_path": session.fs_expand_path(path)? }))
                })
            }

            "session_fs_download_file" => {
                let local_path = get_str_arg(&_args, 1, "local_path")?;
                let remote_path = get_str_arg(&_args, 2, "remote_path")?;
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "status": session.fs_download_file(local_path, remote_path)? }))
                })
            }

            "session_fs_upload_file" => {
                let remote_path = get_str_arg(&_args, 1, "remote_path")?;
                let local_path = get_str_arg(&_args, 2, "local_path")?;
                self.with_session(&_args, |session| {
                    session.fs_upload_file(remote_path, local_path)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            // === Session Post Module Execution ===
            "session_run_post_module" => {
                let module_path = get_str_arg(&_args, 1, "module_path")?;
                let options = parse_options(_args.get(2)).unwrap_or_default();
                self.with_session(&_args, |session| {
                    Ok(serde_json::json!({ "success": session.run_post_module(module_path, options)? }))
                })
            }

            // === Session Process Management (Meterpreter) ===
            "session_process_getpid" => self.with_session(&_args, |session| {
                Ok(serde_json::json!({ "pid": session.process_getpid()? }))
            }),

            "session_process_list" => self.with_session(&_args, |session| {
                Ok(serde_json::json!({ "processes": session.process_list()? }))
            }),

            "session_process_kill" => {
                let pid = _args.get(1).and_then(|v| v.as_i64()).context("Missing pid")?;
                self.with_session(&_args, |session| {
                    session.process_kill(pid)?;
                    Ok(serde_json::json!({ "success": true }))
                })
            }

            "session_process_execute" => {
                let path = get_str_arg(&_args, 1, "path")?;
                let args_str = get_str_arg(&_args, 2, "args")?;
                let hidden = _args.get(3).and_then(|v| v.as_bool()).unwrap_or(false);
                let channelized = _args.get(4).and_then(|v| v.as_bool()).unwrap_or(false);
                self.with_session(&_args, |session| {
                    Ok(session.process_execute(path, args_str, hidden, channelized)?)
                })
            }

            // === Module Execution ===
            "module_exploit" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let payload = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing payload")?;
                let options = parse_options(_args.get(2));

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let session_id = module.exploit(payload, options)?;

                Ok(serde_json::json!({ "session_id": session_id }))
            }

            "module_run" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;
                let options = parse_options(_args.get(1));

                let modules = self.modules.lock();
                let module = modules.get(module_id).context("Module not found")?;
                let success = module.run(options)?;

                Ok(serde_json::json!({ "success": success }))
            }

            "delete_module" => {
                let module_id = _args
                    .get(0)
                    .and_then(|v| v.as_str())
                    .context("Missing module_id")?;

                let mut modules = self.modules.lock();
                let existed = modules.remove(module_id).is_some();

                Ok(serde_json::json!({ "deleted": existed }))
            }

            _ => {
                warn!("Unknown method called: {}", method);
                anyhow::bail!("Unknown method: {}", method)
            }
        }
    }

    /// Log daemon statistics
    fn log_statistics(&self) {
        let requests = self.request_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let req_util = self.request_buffer.utilization();
        let resp_util = self.response_buffer.utilization();

        info!(
            "Stats: {} requests, {} errors, req: {:.1}%, resp: {:.1}%",
            requests,
            errors,
            req_util * 100.0,
            resp_util * 100.0
        );
    }
}

/// Setup signal handling for graceful shutdown
async fn handle_signals(mut signals: Signals, shutdown: Arc<AtomicBool>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT => {
                info!("Received shutdown signal, setting shutdown flag");
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Initialize logging
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("Assassinate Daemon starting...");
    info!("Shared memory: {}", args.shm_name);
    info!("Buffer size: {} bytes", args.buffer_size);

    // Log ASSASSINATE_WORKSPACE for debugging credential tests
    let workspace_env =
        std::env::var("ASSASSINATE_WORKSPACE").unwrap_or_else(|_| "not set".to_string());
    info!("ASSASSINATE_WORKSPACE: {}", workspace_env);

    // Create cleanup guard early - this will run even on panic thanks to Drop
    let _cleanup_guard = CleanupGuard::new(args.shm_name.clone());

    // Set up panic handler to ensure cleanup happens
    let shm_name_for_panic = args.shm_name.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("Daemon panicked: {}", panic_info);
        // Manual cleanup in panic handler as extra safety
        let request_shm_path = format!("/dev/shm/{}_req", shm_name_for_panic);
        let response_shm_path = format!("/dev/shm/{}_resp", shm_name_for_panic);
        let _ = std::fs::remove_file(&request_shm_path);
        let _ = std::fs::remove_file(&response_shm_path);
    }));

    // Initialize Metasploit Framework
    info!("Initializing Metasploit Framework...");
    // Priority: 1) CLI arg, 2) MSF_ROOT env var, 3) Default
    let msf_root_env = std::env::var("MSF_ROOT").ok();
    let msf_root = args
        .msf_root
        .as_ref()
        .and_then(|p| p.to_str())
        .or_else(|| msf_root_env.as_deref())
        .unwrap_or("/usr/share/metasploit-framework");
    bridge::init_metasploit(msf_root)
        .context("Failed to initialize Metasploit Ruby environment")?;

    let framework = Framework::new(None).context("Failed to create MSF framework instance")?;
    info!("MSF Framework initialized: {}", framework.version()?);

    // Create ring buffers for bidirectional IPC
    info!("Creating IPC ring buffers...");
    let request_buffer_name = format!("{}_req", args.shm_name);
    let response_buffer_name = format!("{}_resp", args.shm_name);

    let request_buffer = RingBuffer::create(&request_buffer_name, args.buffer_size)
        .context("Failed to create request ring buffer")?;
    let response_buffer = RingBuffer::create(&response_buffer_name, args.buffer_size)
        .context("Failed to create response ring buffer")?;
    info!("Ring buffers created successfully");

    // Setup signal handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let signals = Signals::new([SIGTERM, SIGINT]).context("Failed to setup signal handling")?;
    let signals_handle = signals.handle();

    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        handle_signals(signals, shutdown_clone).await;
    });

    // Create and run daemon
    let daemon = Daemon::new(framework, request_buffer, response_buffer, shutdown);
    let result = daemon.run().await;

    // Cleanup
    signals_handle.close();
    info!("Daemon stopped");

    // Note: CleanupGuard's Drop will handle shared memory cleanup automatically

    result
}
