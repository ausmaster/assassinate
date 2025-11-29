use anyhow::{Context, Result};
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
                let host_id = db.report_host_raw(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "host_id": host_id }))
            }

            "db_report_service" => {
                let db = self.framework.db()?;
                let service_id = db.report_service_raw(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "service_id": service_id }))
            }

            "db_report_vuln" => {
                let db = self.framework.db()?;
                let vuln_id = db.report_vuln_raw(parse_options(_args.get(0)))?;
                Ok(serde_json::json!({ "vuln_id": vuln_id }))
            }

            "db_report_cred" => {
                let db = self.framework.db()?;
                let cred_id = db.report_cred_raw(parse_options(_args.get(0)))?;
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

            "session_info" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let info = session.info()?;
                    Ok(serde_json::json!({ "info": info }))
                } else {
                    Ok(serde_json::json!({ "info": null }))
                }
            }

            "session_type" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let session_type = session.session_type()?;
                    Ok(serde_json::json!({ "type": session_type }))
                } else {
                    Ok(serde_json::json!({ "type": null }))
                }
            }

            "session_alive" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let alive = session.alive()?;
                    Ok(serde_json::json!({ "alive": alive }))
                } else {
                    Ok(serde_json::json!({ "alive": false }))
                }
            }

            "session_read" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let length = _args.get(1).and_then(|v| v.as_u64()).map(|v| v as usize);

                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let data = session.read_raw(length)?;
                    Ok(serde_json::json!({ "data": data }))
                } else {
                    anyhow::bail!("Session not found")
                }
            }

            "session_write" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let data = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing data")?;

                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let bytes_written = session.write_raw(data)?;
                    Ok(serde_json::json!({ "bytes_written": bytes_written }))
                } else {
                    anyhow::bail!("Session not found")
                }
            }

            "session_execute" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let command = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing command")?;

                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let output = session.execute_raw(command)?;
                    Ok(serde_json::json!({ "output": output }))
                } else {
                    anyhow::bail!("Session not found")
                }
            }

            "session_run_cmd" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let command = _args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .context("Missing command")?;

                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let output = session.run_cmd_raw(command)?;
                    Ok(serde_json::json!({ "output": output }))
                } else {
                    anyhow::bail!("Session not found")
                }
            }

            "session_desc" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let desc = session.desc()?;
                    Ok(serde_json::json!({ "desc": desc }))
                } else {
                    Ok(serde_json::json!({ "desc": null }))
                }
            }

            "session_host" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let host = session.session_host()?;
                    Ok(serde_json::json!({ "host": host }))
                } else {
                    Ok(serde_json::json!({ "host": null }))
                }
            }

            "session_port" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let port = session.session_port()?;
                    Ok(serde_json::json!({ "port": port }))
                } else {
                    Ok(serde_json::json!({ "port": null }))
                }
            }

            "session_tunnel_peer" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let tunnel_peer = session.tunnel_peer()?;
                    Ok(serde_json::json!({ "tunnel_peer": tunnel_peer }))
                } else {
                    Ok(serde_json::json!({ "tunnel_peer": null }))
                }
            }

            "session_target_host" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let target_host = session.target_host()?;
                    Ok(serde_json::json!({ "target_host": target_host }))
                } else {
                    Ok(serde_json::json!({ "target_host": null }))
                }
            }

            "session_via_exploit" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let via_exploit = session.via_exploit()?;
                    Ok(serde_json::json!({ "via_exploit": via_exploit }))
                } else {
                    Ok(serde_json::json!({ "via_exploit": null }))
                }
            }

            "session_via_payload" => {
                let session_id = _args
                    .get(0)
                    .and_then(|v| v.as_i64())
                    .context("Missing session_id")?;
                let sessions = self.framework.sessions()?;
                if let Some(sess_val) = sessions.get_raw(session_id)? {
                    let session = bridge::Session::from_raw(sess_val, session_id);
                    let via_payload = session.via_payload()?;
                    Ok(serde_json::json!({ "via_payload": via_payload }))
                } else {
                    Ok(serde_json::json!({ "via_payload": null }))
                }
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

    // Initialize Metasploit Framework
    info!("Initializing Metasploit Framework...");
    let msf_root = args
        .msf_root
        .as_ref()
        .and_then(|p| p.to_str())
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

    result
}
