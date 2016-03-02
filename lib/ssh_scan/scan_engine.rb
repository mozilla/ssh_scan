require 'socket'
require 'ssh_scan/client'

module SSHScan
  class ScanEngine

    def scan(opts)
      target = opts[:target]
      port = opts[:port]
      policy = opts[:policy_file]

      # Connect and get results
      client = SSHScan::Client.new(target, port)
      client.connect()
      result = client.get_kex_result()

      # If policy defined, then add compliance results
      unless policy.nil?
        policy_mgr = SSHScan::PolicyManager.new(result, policy)
        result['compliance'] = policy_mgr.compliance_results
      end

      return result
    end
  end
end
