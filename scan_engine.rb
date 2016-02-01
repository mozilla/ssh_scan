module SSH
  class ScanEngine

    # TODO: this is pretty crude, clean this up a bit

    def scan(ip, port, policy)
      # Do initial protocol exchange
      sock = TCPSocket.new(ip, port)
      server_protocol = sock.gets
      sock.puts(SSH::Constants::DEFAULT_PROTOCOL)

      # Perform Key Initialization Exchange
      sock.write(SSH::Constants::DEFAULT_KEY_INIT_RAW)
      resp = sock.read(4)
      resp += sock.read(resp.unpack("N").first)
      kex_init_response = SSH::KeyExchangeInit.read(resp)
      sock.close

      # Assemble and print results
      result = {
        :ip => ip,
        :port => port,
        :server_banner => server_protocol.chomp
      }
      result.merge!(kex_init_response.to_hash)

      # Evaluate for Policy Compliance
      policy = SSH::IntermediatePolicy.new
      policy_mgr = SSH::PolicyManager.new(result, policy)
      result['compliance'] = policy_mgr.compliance_results

      return result
    end
  end
end
