#!/usr/bin/env ruby
# frozen_string_literal: true

require 'benchmark'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "  #{name}: #{(time * 1000).round(2)}ms"
  result
end

puts "=" * 60
puts "MSF DEEP DIVE TIMING"
puts "=" * 60

# ============================================================
# PART 1: Framework initialization breakdown
# ============================================================
puts "\n" + "=" * 60
puts "PART 1: FRAMEWORK INIT BREAKDOWN"
puts "=" * 60

timed("require 'pathname'") { require 'pathname' }
timed("require 'rubygems'") { require 'rubygems' }

# What does msfenv actually load?
puts "\n--- msfenv breakdown ---"
msf_base = File.expand_path('../..', __FILE__)
msf_base = '/home/astark/Projects/metasploit-framework'

timed("Set load paths") do
  $LOAD_PATH.unshift(File.join(msf_base, 'lib'))
  $LOAD_PATH.unshift(File.join(msf_base, 'test', 'lib'))
end

timed("require 'msfenv'") { require 'msfenv' }

puts "\n--- msf/base breakdown ---"
timed("require 'msf/base'") { require 'msf/base' }

puts "\n--- Framework.create breakdown ---"
# Let's see what Framework.create actually does
puts "  (This loads all modules, DB connections, etc.)"

framework = nil
timed("Msf::Simple::Framework.create (TOTAL)") do
  framework = Msf::Simple::Framework.create
end

# Try creating another framework to see if it's faster (cached)
puts "\n--- Second Framework.create (should be faster?) ---"
framework2 = nil
timed("Msf::Simple::Framework.create (2nd time)") do
  framework2 = Msf::Simple::Framework.create
end

# ============================================================
# PART 2: What makes Framework.create slow?
# ============================================================
puts "\n" + "=" * 60
puts "PART 2: FRAMEWORK INTERNALS"
puts "=" * 60

puts "\n--- Module counts (what was loaded) ---"
timed("Count exploits") { puts "    Exploits: #{framework.exploits.length}" }
timed("Count payloads") { puts "    Payloads: #{framework.payloads.length}" }
timed("Count auxiliary") { puts "    Auxiliary: #{framework.auxiliary.length}" }
timed("Count post") { puts "    Post: #{framework.post.length}" }
timed("Count encoders") { puts "    Encoders: #{framework.encoders.length}" }
timed("Count nops") { puts "    Nops: #{framework.nops.length}" }

# ============================================================
# PART 3: Shell operations deep dive
# ============================================================
puts "\n" + "=" * 60
puts "PART 3: SHELL OPS DEEP DIVE"
puts "=" * 60

# First, clean up any existing sessions
puts "\n--- Cleaning up existing sessions ---"
framework.sessions.each_key do |sid|
  framework.sessions[sid].kill rescue nil
end
sleep 0.5

puts "\n--- Creating session for shell tests ---"
exploit = framework.exploits.create('linux/samba/is_known_pipename')
exploit.datastore['RHOSTS'] = '172.19.0.3'
exploit.datastore['SMB_SHARE_NAME'] = 'myshare'
exploit.datastore['SMB_USER'] = 'root'
exploit.datastore['SMB_PASS'] = 'root'

# Capture output to see errors
output_buffer = Rex::Ui::Text::Output::Buffer.new
exploit.datastore['VERBOSE'] = true

session = nil
timed("exploit_simple (RunAsJob: true)") do
  exploit.exploit_simple(
    'Payload' => 'cmd/unix/interact',
    'RunAsJob' => true,
    'LocalInput' => Rex::Ui::Text::Input::Buffer.new,
    'LocalOutput' => output_buffer
  )
end

# Skip output buffer for now

# Poll for session
puts "  Polling for session..."
poll_start = Time.now
while Time.now - poll_start < 30
  if framework.sessions.length > 0
    session = framework.sessions.values.first
    break
  end
  sleep 0.1
end
poll_time = (Time.now - poll_start) * 1000
puts "  Poll time: #{poll_time.round(2)}ms"

unless session
  puts "  Failed to get session after polling!"
  puts "  Sessions: #{framework.sessions.keys}"
  puts "  Jobs: #{framework.jobs.keys}"
  # Can't dump output buffer
  exit 1
end

puts "  Got session #{session.sid}"

puts "\n--- Raw socket operations ---"

# Get the underlying stream
rstream = session.rstream
puts "  rstream class: #{rstream.class}"

# Time raw socket write
timed("rstream.write('id\\n')") do
  rstream.write("id\n")
end

sleep 0.05  # Let command execute

# Time raw socket read with different methods
timed("rstream.get_once(-1, 0.1)") do
  data = rstream.get_once(-1, 0.1)
  puts "    Data: #{data.inspect[0..40]}" if data
end

# Clear buffer
sleep 0.1
rstream.get_once(-1, 0.1) rescue nil

puts "\n--- shell_write internals ---"
# Look at what shell_write actually does
puts "  shell_write source location: #{session.method(:shell_write).source_location rescue 'N/A'}"

# Time multiple shell_writes
5.times do |i|
  timed("shell_write ##{i+1}") do
    session.shell_write("echo test#{i}\n")
  end
end

sleep 0.2
session.shell_read(-1, 0.1) rescue nil  # Clear buffer

puts "\n--- shell_read internals ---"
puts "  shell_read source location: #{session.method(:shell_read).source_location rescue 'N/A'}"

session.shell_write("echo hello\n")
sleep 0.05

5.times do |i|
  timed("shell_read(-1, 0.1) ##{i+1}") do
    data = session.shell_read(-1, 0.1)
    puts "    Got: #{data.inspect[0..30]}" if data && !data.empty?
  end
end

puts "\n--- IO.select timing ---"
# Test if IO.select itself is slow
10.times do |i|
  timed("IO.select([rstream], nil, nil, 0.01) ##{i+1}") do
    IO.select([rstream], nil, nil, 0.01)
  end
end

puts "\n--- Framework events overhead ---"
# shell_read calls framework.events.on_session_output
# Let's see if that's slow
puts "  Checking if events are adding overhead..."

# Temporarily check event handlers
event_count = framework.events.instance_variable_get(:@listeners)&.length rescue 'N/A'
puts "  Event listeners: #{event_count}"

# ============================================================
# PART 4: Compare with raw socket (no MSF)
# ============================================================
puts "\n" + "=" * 60
puts "PART 4: RAW SOCKET COMPARISON"
puts "=" * 60

require 'socket'

puts "\n--- Direct TCP to pre-existing shell on 4445 ---"
sock = nil
timed("TCPSocket.new('172.19.0.3', 4445)") do
  sock = TCPSocket.new('172.19.0.3', 4445)
end

timed("sock.write('id\\n')") do
  sock.write("id\n")
end

timed("IO.select + sock.read_nonblock") do
  IO.select([sock], nil, nil, 0.1)
  data = sock.read_nonblock(4096) rescue nil
  puts "    Data: #{data.inspect[0..40]}" if data
end

sock.close

puts "\n--- Multiple raw socket operations ---"
sock = TCPSocket.new('172.19.0.3', 4445)

5.times do |i|
  timed("raw write+read ##{i+1}") do
    sock.write("echo test#{i}\n")
    IO.select([sock], nil, nil, 0.1)
    data = sock.read_nonblock(4096) rescue nil
  end
end

sock.close

# ============================================================
# CLEANUP
# ============================================================
puts "\n" + "=" * 60
puts "CLEANUP"
puts "=" * 60

session.kill rescue nil

puts "\nDone!"
