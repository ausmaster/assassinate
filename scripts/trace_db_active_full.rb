#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Trace exactly what happens in framework.db.active
#

require 'benchmark'

puts "=" * 60
puts "TRACING db.active FULLY"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create
db = framework.db

puts "\n--- DB Manager state ---"
puts "  usable: #{db.usable}"
puts "  migrated: #{db.migrated}"
puts "  class: #{db.class}"

# Monkey-patch to trace
class << db
  alias_method :original_connection_established?, :connection_established?

  def connection_established?
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = original_connection_established?
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    puts "      connection_established? took #{elapsed.round(3)}ms, returned #{result}"
    result
  end
end

puts "\n--- Tracing db.active 5 times ---"
5.times do |i|
  puts "\n  Call #{i+1}:"
  time = Benchmark.realtime { db.active }
  puts "    db.active total: #{(time * 1000).round(3)}ms"
end

# Now trace inside connection_established?
puts "\n--- Tracing inside connection_established? ---"

class << db
  def connection_established?
    times = {}
    times[:start] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    begin
      times[:before_with_connection] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      ApplicationRecord.connection_pool.with_connection do |conn|
        times[:got_connection] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        conn.verify!
        times[:after_verify] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
      times[:after_with_connection] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      true
    rescue ActiveRecord::ConnectionNotEstablished, PG::ConnectionBad => error
      times[:exception_caught] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      puts "      Exception: #{error.class}"
      false
    end

    times[:end] = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # Print breakdown
    total = (times[:end] - times[:start]) * 1000
    if times[:exception_caught]
      exc_time = (times[:exception_caught] - times[:start]) * 1000
      puts "      exception path took #{exc_time.round(3)}ms"
    else
      conn_time = (times[:got_connection] - times[:before_with_connection]) * 1000
      verify_time = (times[:after_verify] - times[:got_connection]) * 1000
      puts "      get connection: #{conn_time.round(3)}ms, verify: #{verify_time.round(3)}ms"
    end
    puts "      total: #{total.round(3)}ms"

    times[:exception_caught] ? false : true
  end
end

puts "\n  Re-tracing db.active 3 times:"
3.times do |i|
  puts "\n  Call #{i+1}:"
  time = Benchmark.realtime { db.active }
  puts "    db.active total: #{(time * 1000).round(3)}ms"
end

puts "\nDone!"
