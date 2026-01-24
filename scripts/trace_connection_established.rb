#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Trace exactly what's slow inside connection_established?
#

require 'benchmark'

puts "=" * 60
puts "TRACING connection_established? OVERHEAD"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create

puts "\n--- Breaking down connection_established? ---"

# Manual implementation with timing
5.times do |i|
  puts "\n  Iteration #{i+1}:"

  total_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  # Step 1: Get connection pool
  step1_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  pool = ApplicationRecord.connection_pool
  step1_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - step1_start) * 1000
  puts "    get connection_pool: #{step1_time.round(3)}ms"

  # Step 2: with_connection block
  step2_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    pool.with_connection do |conn|
      step2a_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - step2_start) * 1000
      puts "    with_connection (get conn): #{step2a_time.round(3)}ms"

      # Step 3: verify!
      step3_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      conn.verify!
      step3_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - step3_start) * 1000
      puts "    verify!: #{step3_time.round(3)}ms"
    end
  rescue => e
    step2_err_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - step2_start) * 1000
    puts "    exception caught: #{step2_err_time.round(3)}ms - #{e.class}"
  end

  total_time = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - total_start) * 1000
  puts "    TOTAL: #{total_time.round(3)}ms"
end

puts "\n--- Testing pool.with_connection alone ---"
5.times do |i|
  time = Benchmark.realtime do
    ApplicationRecord.connection_pool.with_connection do |conn|
      # do nothing
    end
  end
  puts "  with_connection #{i+1}: #{(time * 1000).round(3)}ms"
end

puts "\n--- Testing if there's a timeout ---"
puts "  pool.checkout_timeout: #{ApplicationRecord.connection_pool.checkout_timeout rescue 'N/A'}"
puts "  pool.size: #{ApplicationRecord.connection_pool.size rescue 'N/A'}"

# Check for db config
puts "\n--- Database configuration ---"
puts "  db_config: #{ApplicationRecord.connection_db_config rescue 'N/A'}"

puts "\nDone!"
