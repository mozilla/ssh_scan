require 'socket'
require 'ssh_scan/client'
require 'net/ssh'

module SSHScan
  class ScanEngine

    def scan_target(target, opts)
      port = opts[:port]
      policy = opts[:policy_file]
      timeout = opts[:timeout]

      client = SSHScan::Client.new(target, port, timeout)
      client.connect()
      result = client.get_kex_result()
      return result if result.include?(:error)

      # Connect and get results (Net-SSH)
      begin
        net_ssh_session = Net::SSH::Transport::Session.new(target, :port => port, :timeout => timeout)
        raise SSHScan::Error::ClosedConnection.new if net_ssh_session.closed?
        auth_session = Net::SSH::Authentication::Session.new(net_ssh_session, :auth_methods => ["none"])
        auth_session.authenticate("none", "test", "test")
        result['auth_methods'] = auth_session.allowed_auth_methods
        host_key = net_ssh_session.host_keys.first
        net_ssh_session.close
      rescue Net::SSH::ConnectionTimeout => e
        warn("WARNING: net-ssh timed out attempting to connect to service (fingerprints and auth_methods will not be available)")
        result['auth_methods'] = []
        result['fingerprints'] = {}
        result[:error] = e
        result[:error] = SSHScan::Error::ConnectTimeout.new(e.message)
      rescue Net::SSH::Disconnect => e
        warn("WARNING: net-ssh disconnected unexpectedly (fingerprints and auth_methods will not be available)")
        result['auth_methods'] = []
        result['fingerprints'] = {}
        result[:error] = e
        result[:error] = SSHScan::Error::Disconnected.new(e.message)
      rescue Net::SSH::Exception => e
        if e.to_s.match(/could not settle on encryption_client algorithm/)
          warn("WARNING: net-ssh could not find a mutually acceptable encryption algorithm (fingerprints and auth_methods will not be available)")
          result['auth_methods'] = []
          result['fingerprints'] = {}
          result[:error] = e
        elsif e.to_s.match(/could not settle on host_key algorithm/)
          warn("WARNING: net-ssh could not find a mutually acceptable host_key algorithm (fingerprints and auth_methods will not be available)")
          result['auth_methods'] = []
          result['fingerprints'] = {}
          result[:error] = e
        else
          raise e
        end
      else
        #only supporting RSA for the moment
        if host_key.is_a?(OpenSSL::PKey::RSA)
          data_string = OpenSSL::ASN1::Sequence([
           OpenSSL::ASN1::Integer.new(host_key.public_key.n),
           OpenSSL::ASN1::Integer.new(host_key.public_key.e)
          ])

          fingerprint_md5 = OpenSSL::Digest::MD5.hexdigest(data_string.to_der).scan(/../).join(':')
          fingerprint_sha1 = OpenSSL::Digest::SHA1.hexdigest(data_string.to_der).scan(/../).join(':')
          fingerprint_sha256 = OpenSSL::Digest::SHA256.hexdigest(data_string.to_der).scan(/../).join(':')

          result['fingerprints'] = {
           "md5" => fingerprint_md5,
           "sha1" => fingerprint_sha1,
           "sha256" => fingerprint_sha256,
          }
          # Do this only when no errors were reported
          unless policy.nil?
            policy_mgr = SSHScan::PolicyManager.new(result, policy)
            result['compliance'] = policy_mgr.compliance_results
          end
        else
          warn("WARNING: Host key support for #{host_key.class} is not provided yet (fingerprints will not be available)")
          result['fingerprints'] = {}
        end
      end
      return result
    end

    def scan(opts)
      targets = opts[:targets]
      threads = opts[:threads] || 5

      results = []

      work_queue = Queue.new
      targets.each {|x| work_queue.push x }
      workers = (0...threads).map do |worker_num|
        Thread.new do
          begin
            while target = work_queue.pop(true)
              results << scan_target(target, opts)
            end
          rescue ThreadError => e
            raise e unless e.to_s.match(/queue empty/)
          end
        end
      end
      workers.map(&:join)

      return results
    end
  end
end
