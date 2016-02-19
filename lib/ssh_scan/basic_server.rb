require 'sinatra'
require 'ssh_scan'

get '/api/v1/scan/:ip' do
  if ip = params['ip']
    policy = SSHScan::Policy.from_file(File.expand_path("../../policies/mozilla_intermediate.yml", __FILE__))
    scan_engine = SSHScan::ScanEngine.new()
    result = scan_engine.scan(ip, 22, policy)
    content_type :json
    return JSON.pretty_generate(result)
  else
    status 500
    body "Error: did not supply a valid IP to be scanned"
  end
end
