require 'sinatra'
require 'protocol'
require 'socket'
require 'policy'
require 'constants'
require 'scan_engine'

get '/api/v1/scan/:ip' do
  if ip = params['ip']
    policy = SSHScan::IntermediatePolicy.new
    scan_engine = SSHScan::ScanEngine.new()
    result = scan_engine.scan(ip, 22, policy)
    content_type :json
    return JSON.pretty_generate(result)
  else
    status 500
    body "Error: did not supply a valid IP to be scanned"
  end
end
