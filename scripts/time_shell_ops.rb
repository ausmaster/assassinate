#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Focus specifically on shell operation timing.
# Uses raw sockets to compare with MSF overhead.
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
SHELL_PORT = 4445

puts "=" * 60
puts "SHELL OPERATIONS TIMING"
puts "=" * 60
puts "Target: #{TARGET}:#{SHELL_PORT}"

# ============================================================
# PART 1: Raw Ruby Socket (baseline)
# ============================================================
puts "\n" + "=" * 60
puts "PART 1: RAW RUBY SOCKET (BASELINE)"
puts "=" * 60

sock = nil
timed("TCPSocket.new") do
  sock = TCPSocket.new(TARGET, SHELL_PORT)
end

puts "\n--- Write operations ---"
10.times do |i|
  timed("sock.write ##{i+1}") do
    sock.write("echo test#{i}\n")
  end
end

puts "\n--- Read operations (with IO.select) ---"
sleep 0.1  # Let commands execute

10.times do |i|
  timed("IO.select + read_nonblock ##{i+1}") do
    ready = IO.select([sock], nil, nil, 0.1)
    if ready
      data = sock.read_nonblock(4096) rescue nil
      # puts "    Data: #{data.inspect[0..30]}" if data && i == 0
    end
  end
end

puts "\n--- Combined write+select+read ---"
10.times do |i|
  timed("write+select+read ##{i+1}") do
    sock.write("id\n")
    IO.select([sock], nil, nil, 0.1)
    data = sock.read_nonblock(4096) rescue nil
  end
end

sock.close

# ============================================================
# PART 2: Rex Socket (MSF's socket wrapper)
# ============================================================
puts "\n" + "=" * 60
puts "PART 2: REX SOCKET (MSF's wrapper)"
puts "=" * 60

require 'msfenv'
require 'rex/socket'

rex_sock = nil
timed("Rex::Socket::Tcp.create") do
  rex_sock = Rex::Socket::Tcp.create(
    'PeerHost' => TARGET,
    'PeerPort' => SHELL_PORT
  )
end

puts "\n--- Rex write operations ---"
10.times do |i|
  timed("rex_sock.write ##{i+1}") do
    rex_sock.write("echo rextest#{i}\n")
  end
end

puts "\n--- Rex get_once operations ---"
sleep 0.1

10.times do |i|
  timed("rex_sock.get_once(-1, 0.1) ##{i+1}") do
    data = rex_sock.get_once(-1, 0.1)
    # puts "    Data: #{data.inspect[0..30]}" if data && i == 0
  end
end

puts "\n--- Rex combined write+get_once ---"
10.times do |i|
  timed("write+get_once ##{i+1}") do
    rex_sock.write("id\n")
    data = rex_sock.get_once(-1, 0.1)
  end
end

rex_sock.close

# ============================================================
# PART 3: CommandShell simulation
# ============================================================
puts "\n" + "=" * 60
puts "PART 3: SIMULATE shell_command LOGIC"
puts "=" * 60

# Recreate what MSF's shell_command does
sock = TCPSocket.new(TARGET, SHELL_PORT)

def shell_command_simulation(sock, cmd, timeout)
  # This mimics MSF's shell_command implementation
  sock.write(cmd + "\n")

  etime = Time.now.to_f + timeout
  buff = String.new  # Mutable string

  while Time.now.to_f < etime
    ready = IO.select([sock], nil, nil, [timeout, etime - Time.now.to_f].min)
    break unless ready

    begin
      data = sock.read_nonblock(4096)
      buff << data if data
    rescue IO::WaitReadable
      # No data available
    rescue EOFError
      break
    end

    timeout = etime - Time.now.to_f
  end

  buff
end

puts "\n--- shell_command simulation with different timeouts ---"
[5.0, 2.0, 1.0, 0.5, 0.2, 0.1, 0.05].each do |timeout|
  output = nil
  timed("shell_command_sim(timeout=#{timeout})") do
    output = shell_command_simulation(sock, "id", timeout)
  end
  puts "    Output length: #{output.length}" if output
end

sock.close

# ============================================================
# PART 4: What adds overhead in MSF?
# ============================================================
puts "\n" + "=" * 60
puts "PART 4: MSF FRAMEWORK OVERHEAD"
puts "=" * 60

require 'msf/base'

puts "\n--- Loading MSF framework ---"
framework = nil
timed("Msf::Simple::Framework.create") do
  framework = Msf::Simple::Framework.create
end

puts "\n--- Check event system overhead ---"
# The shell_read method calls framework.events.on_session_output
# Let's see how slow event dispatch is

class FakeSession
  attr_accessor :framework
  def log_source; nil; end
end

fake = FakeSession.new
fake.framework = framework

10.times do |i|
  timed("framework.events.on_session_output ##{i+1}") do
    framework.events.on_session_output(fake, "test data #{i}") rescue nil
  end
end

10.times do |i|
  timed("framework.events.on_session_command ##{i+1}") do
    framework.events.on_session_command(fake, "test cmd #{i}") rescue nil
  end
end

puts "\nDone!"
