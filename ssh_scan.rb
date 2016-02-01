require 'protocol'
require 'socket'
require 'policy'
require 'constants'
require 'scan_engine'

# Usage: ruby -I ./ ssh_scan.rb 192.168.1.1

# Populate the info we need to perform a scan
ip = ARGV[0].chomp
port = ARGV[1] || 22
policy = SSH::IntermediatePolicy.new

# Perform scan and get results
scan_engine = SSH::ScanEngine.new()
result = scan_engine.scan(ip, port, policy)

puts JSON.pretty_generate(result)
