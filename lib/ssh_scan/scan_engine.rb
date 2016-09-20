require 'socket'
require 'ssh_scan/client'
require 'ssh_scan/crypto'
require 'ssh_scan/fingerprint_database'
require 'net/ssh'

module SSHScan
  class ScanEngine

    def scan_target(socket, opts)
      target, port = socket.chomp.split(':')
      if port.nil?
        port = 22
      end
      timeout = opts[:timeout]
      result = []

      start_time = Time.now

      if target.fqdn?
        if target.resolve_fqdn_as_ipv6.nil?
          client = SSHScan::Client.new(target.resolve_fqdn_as_ipv4.to_s, port, timeout)
          client.connect()
          result = client.get_kex_result()
          result[:hostname] = target
          return result if result.include?(:error)
        else
          client = SSHScan::Client.new(target.resolve_fqdn_as_ipv6.to_s, port, timeout)
          client.connect()
          result = client.get_kex_result()
          if result.include?(:error)
            client = SSHScan::Client.new(target.resolve_fqdn_as_ipv4.to_s, port, timeout)
            client.connect()
            result = client.get_kex_result()
            result[:hostname] = target
            return result if result.include?(:error)
          end
        end
      else
        client = SSHScan::Client.new(target, port, timeout)
        client.connect()
        result = client.get_kex_result()
        result[:hostname] = ""
        return result if result.include?(:error)
      end

      # Connect and get results (Net-SSH)
      begin
        net_ssh_session = Net::SSH::Transport::Session.new(
                            target,
                            :port => port,
                            :timeout => timeout,
                            :paranoid => Net::SSH::Verifiers::Null.new
                          )
        raise SSHScan::Error::ClosedConnection.new if net_ssh_session.closed?
        auth_session = Net::SSH::Authentication::Session.new(net_ssh_session, :auth_methods => ["none"])
        auth_session.authenticate("none", "test", "test")
        result['auth_methods'] = auth_session.allowed_auth_methods
        host_key = net_ssh_session.host_keys.first
        net_ssh_session.close
      rescue Net::SSH::ConnectionTimeout => e
        result[:error] = e
        result[:error] = SSHScan::Error::ConnectTimeout.new(e.message)
      rescue Net::SSH::Disconnect => e
        result[:error] = e
        result[:error] = SSHScan::Error::Disconnected.new(e.message)
      rescue Net::SSH::Exception => e
        if e.to_s.match(/could not settle on/)
          result[:error] = e
        else
          raise e
        end
      else
        pkey = SSHScan::Crypto::PublicKey.new(host_key)
        if pkey.is_supported?
          result['fingerprints'] = {
            "md5" => pkey.fingerprint_md5,
            "sha1" => pkey.fingerprint_sha1,
            "sha256" => pkey.fingerprint_sha256,
          }
        end
      end

      # Add scan times
      end_time = Time.now
      result['start_time'] = start_time.to_s
      result['end_time'] = end_time.to_s
      result['scan_duration_seconds'] = end_time - start_time

      return result
    end

    def scan(opts)
      sockets = opts[:sockets]
      threads = opts[:threads] || 5
      logger = opts[:logger]

      results = []

      work_queue = Queue.new
      sockets.each {|x| work_queue.push x }
      workers = (0...threads).map do |worker_num|
        Thread.new do
          begin
            while socket = work_queue.pop(true)
              logger.info("Started ssh_scan of #{socket}")
              results << scan_target(socket, opts)
              logger.info("Completed ssh_scan of #{socket}")
            end
          rescue ThreadError => e
            raise e unless e.to_s.match(/queue empty/)
          end
        end
      end
      workers.map(&:join)

      # Add all the fingerprints to our peristent FingerprintDatabase
      fingerprint_db = SSHScan::FingerprintDatabase.new(opts[:fingerprint_database])
      results.each do |result|
        fingerprint_db.clear_fingerprints(result[:ip])
        if result['fingerprints']
          result['fingerprints'].values.each do |fingerprint|
            fingerprint_db.add_fingerprint(fingerprint, result[:ip])
          end
        end
      end

      # Decorate all the results with duplicate keys
      results.each do |result|
        if result['fingerprints']
          ip = result[:ip]
          result['duplicate_host_key_ips'] = []
          result['fingerprints'].values.each do |fingerprint|
            fingerprint_db.find_fingerprints(fingerprint).each do |other_ip|
              next if ip == other_ip
              result['duplicate_host_key_ips'] << other_ip
            end
          end
          result['duplicate_host_key_ips'].uniq!        
        end
      end

      # Decorate all the results with compliance information
      results.each do |result|
        # Do this only when we have all the information we need
        if !opts[:policy_file].nil? &&
           !result[:key_algorithms].nil? &&
           !result[:server_host_key_algorithms].nil? &&
           !result[:encryption_algorithms_client_to_server].nil? &&
           !result[:encryption_algorithms_server_to_client].nil? &&
           !result[:mac_algorithms_client_to_server].nil? &&
           !result[:mac_algorithms_server_to_client].nil? &&
           !result[:compression_algorithms_client_to_server].nil? &&
           !result[:compression_algorithms_server_to_client].nil? &&
           !result[:languages_client_to_server].nil? &&
           !result[:languages_server_to_client].nil?
          policy_mgr = SSHScan::PolicyManager.new(result, opts[:policy_file])
          result['compliance'] = policy_mgr.compliance_results
        end
      end

      return results
    end
  end
end
