#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Check MSF database configuration and connection timeout
#

require 'benchmark'

puts "=" * 60
puts "CHECKING DATABASE CONFIGURATION"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create
db = framework.db

puts "\n=== Database configuration ==="
current = db.instance_variable_get(:@current_data_service)
puts "  driver: #{current.driver}"
puts "  error: #{current.error}"

# Check database.yml
db_config_path = File.expand_path("~/.msf4/database.yml")
if File.exist?(db_config_path)
  puts "\n=== ~/.msf4/database.yml ==="
  puts File.read(db_config_path)
else
  puts "\n  No database.yml found"
end

# Check what connection_established? does
puts "\n=== Timing breakdown of connection_established? ==="
5.times do |i|
  start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    ApplicationRecord.connection_pool.with_connection do |conn|
      conn.verify!
    end
  rescue => e
    end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "  #{i+1}: #{((end_time - start_time) * 1000).round(3)}ms - #{e.class}"
  end
end

# Check if PostgreSQL is running
puts "\n=== PostgreSQL status ==="
puts `pg_isready 2>&1`

puts "\nDone!"
