use anyhow::{Context, Result};
use assassinate_bridge::Framework;
use assassinate_ipc::{protocol, IpcError, RingBuffer, DEFAULT_BUFFER_SIZE, DEFAULT_SHM_NAME};
use clap::Parser;
use futures::stream::StreamExt;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{error, info, warn};

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
    ring_buffer: RingBuffer,
    shutdown: Arc<AtomicBool>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl Daemon {
    /// Create a new daemon instance
    fn new(framework: Framework, ring_buffer: RingBuffer, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            framework,
            ring_buffer,
            shutdown,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Main event loop - processes IPC requests
    async fn run(&self) -> Result<()> {
        info!("Daemon started - waiting for requests");
        let mut last_stats_log = Instant::now();
        let stats_interval = Duration::from_secs(60);

        while !self.shutdown.load(Ordering::Relaxed) {
            match self.ring_buffer.try_read() {
                Ok(data) => {
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
                    // No data available - yield and sleep briefly
                    tokio::task::yield_now().await;
                    sleep(Duration::from_micros(10)).await;
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
        let (call_id, method, args) =
            protocol::deserialize_call(data).context("Failed to deserialize request")?;

        let response = match self.dispatch_call(&method, args).await {
            Ok(result) => protocol::serialize_response(call_id, result)?,
            Err(e) => {
                let error_msg = format!("{:#}", e);
                protocol::serialize_error(call_id, "CallFailed", &error_msg)?
            }
        };

        self.ring_buffer
            .try_write(&response)
            .context("Failed to write response to ring buffer")?;

        Ok(())
    }

    /// Dispatch method call to MSF framework
    async fn dispatch_call(
        &self,
        method: &str,
        _args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        match method {
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

            "list_sessions" => {
                let session_manager = self
                    .framework
                    .sessions()
                    .context("Failed to get session manager")?;

                let session_ids = session_manager
                    .list()
                    .context("Failed to list sessions")?;

                Ok(serde_json::json!({ "session_ids": session_ids }))
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
        let utilization = self.ring_buffer.utilization();

        info!(
            "Stats: {} requests, {} errors, {:.1}% buffer utilization",
            requests,
            errors,
            utilization * 100.0
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
    assassinate_bridge::init_metasploit(msf_root)
        .context("Failed to initialize Metasploit Ruby environment")?;

    let framework = Framework::new(None).context("Failed to create MSF framework instance")?;
    info!("MSF Framework initialized: {}", framework.version()?);

    // Create ring buffer for IPC
    info!("Creating IPC ring buffer...");
    let ring_buffer = RingBuffer::create(&args.shm_name, args.buffer_size)
        .context("Failed to create ring buffer")?;
    info!("Ring buffer created successfully");

    // Setup signal handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let signals = Signals::new([SIGTERM, SIGINT]).context("Failed to setup signal handling")?;
    let signals_handle = signals.handle();

    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        handle_signals(signals, shutdown_clone).await;
    });

    // Create and run daemon
    let daemon = Daemon::new(framework, ring_buffer, shutdown);
    let result = daemon.run().await;

    // Cleanup
    signals_handle.close();
    info!("Daemon stopped");

    result
}
