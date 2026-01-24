#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Test if the exception handling is the slow part of db.active
#

require 'benchmark'

puts "=" * 60
puts "TESTING EXCEPTION OVERHEAD"
puts "=" * 60

require 'msfenv'
require 'msf/base'

framework = Msf::Simple::Framework.create

puts "\n--- Raising/catching exception 5x ---"
5.times do |i|
  time = Benchmark.realtime do
    begin
      ApplicationRecord.connection_pool.with_connection do
        ApplicationRecord.connection.verify!
      end
    rescue ActiveRecord::ConnectionNotEstablished, PG::ConnectionBad => error
      # caught
    end
  end
  puts "  exception #{i+1}: #{(time * 1000).round(3)}ms"
end

puts "\n--- Just checking if pool exists (no exception) ---"
5.times do |i|
  time = Benchmark.realtime do
    begin
      pool = ApplicationRecord.connection_pool
      pool.connected?
    rescue
      false
    end
  end
  puts "  pool check #{i+1}: #{(time * 1000).round(3)}ms"
end

puts "\n--- Checking usable/migrated without connection_established? ---"
5.times do |i|
  time = Benchmark.realtime do
    framework.db.usable && framework.db.migrated
  end
  puts "  usable && migrated #{i+1}: #{(time * 1000).round(3)}ms"
end

puts "\n--- Full db.active check ---"
5.times do |i|
  time = Benchmark.realtime do
    framework.db.active
  end
  puts "  db.active #{i+1}: #{(time * 1000).round(3)}ms"
end

puts "\nDone!"
