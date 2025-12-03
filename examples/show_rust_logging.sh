#!/bin/bash
# Demonstration of Rust daemon DEBUG logging
# This script shows the detailed structured logging from the Rust daemon

set -e

echo "=========================================================================="
echo "Rust Daemon Debug Logging Demonstration"
echo "=========================================================================="
echo ""

# Kill any existing daemon
pkill -f "rust/daemon" 2>/dev/null || true
sleep 1

# Start daemon with DEBUG logging
echo "Starting daemon with DEBUG log level..."
./rust/daemon/target/release/daemon \
    --msf-root /home/aus/PycharmProjects/assassinate/metasploit-framework \
    --log-level debug \
    > /tmp/rust_daemon_debug.log 2>&1 &

DAEMON_PID=$!
echo "Daemon started with PID: $DAEMON_PID"
echo ""

# Wait for daemon to initialize
echo "Waiting for daemon to initialize..."
sleep 5

# Run a simple Python script that makes some calls
echo "Making RPC calls with Python client..."
ASSASSINATE_LOG_LEVEL=INFO uv run python3 << 'PYTHON_SCRIPT'
import asyncio
from assassinate.ipc.client import MsfClient

async def main():
    async with MsfClient() as client:
        # Make several calls to generate log entries
        version = await client.framework_version()
        print(f"Got version: {version['version']}")

        exploits = await client.list_modules("exploit")
        print(f"Found {len(exploits)} exploits")

        results = await client.search("ftp")
        print(f"Search found {len(results)} modules")

asyncio.run(main())
PYTHON_SCRIPT

echo ""
echo "Stopping daemon..."
kill $DAEMON_PID
wait $DAEMON_PID 2>/dev/null || true

echo ""
echo "=========================================================================="
echo "Rust Daemon DEBUG Log Output:"
echo "=========================================================================="
echo ""

# Show the debug logs with highlighting
grep -E "(Processing RPC|RPC call|Request completed|dispatch_ms|total_ms|Daemon started)" /tmp/rust_daemon_debug.log || \
grep -A 3 "DEBUG" /tmp/rust_daemon_debug.log | tail -40 || \
tail -40 /tmp/rust_daemon_debug.log

echo ""
echo "=========================================================================="
echo "Full log available at: /tmp/rust_daemon_debug.log"
echo "=========================================================================="
