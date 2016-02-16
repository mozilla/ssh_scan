require 'ssh_scan'

# Usage: ruby ssh_scan.rb 192.168.1.1

# Populate the info we need to perform a scan
ip = ARGV[0].chomp
port = ARGV[1].nil? ? 22 : ARGV[1].to_i
policy = SSHScan::IntermediatePolicy.new

# Perform scan and get results
scan_engine = SSHScan::ScanEngine.new()
result = scan_engine.scan(ip, port, policy)

puts JSON.pretty_generate(result)
