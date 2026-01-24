#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Verify that database writes are causing the overhead
#

require 'benchmark'

def timed(name)
  result = nil
  time = Benchmark.realtime { result = yield }
  puts "  #{name}: #{(time * 1000).round(3)}ms"
  result
end

puts "=" * 60
puts "VERIFYING DATABASE OVERHEAD"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create

# Check database status
puts "\n--- Database Status ---"
puts "  db.active: #{framework.db.active}"
puts "  db.driver: #{framework.db.driver rescue 'N/A'}"

if framework.db.active
  puts "\n  DATABASE IS ACTIVE - this is causing the 420ms overhead!"
  puts "  Each shell_write triggers framework.db.report_session_event()"

  # Time a direct database write
  puts "\n--- Direct database write timing ---"
  if framework.sessions.length > 0
    session = framework.sessions.values.first

    5.times do |i|
      timed("report_session_event ##{i+1}") do
        framework.db.report_session_event({
          :etype => 'command',
          :session => session,
          :command => "test command #{i}"
        })
      end
    end
  else
    puts "  No session available for testing"
  end
else
  puts "\n  DATABASE IS NOT ACTIVE"
  puts "  The 420ms overhead must be coming from somewhere else..."
end

# Check session event subscribers
puts "\n--- Session Event Subscribers ---"
subscribers = framework.events.instance_variable_get(:@session_event_subscribers) rescue []
puts "  Count: #{subscribers.length}"
subscribers.each_with_index do |sub, i|
  puts "    #{i}: #{sub.class}"
end

puts "\nDone!"
