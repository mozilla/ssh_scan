require 'socket'
require 'ssh_scan/constants'
require 'ssh_scan/protocol'

module SSHScan
  class Client
    def initialize(ip, port)
      @ip = ip
      @port = port
      @client_protocol = SSHScan::Constants::DEFAULT_CLIENT_PROTOCOL
      @server_protocol = nil
      @kex_init_raw = SSHScan::Constants::DEFAULT_KEY_INIT_RAW
    end

    def connect()
      @sock = TCPSocket.new(@ip, @port)
      @server_protocol = @sock.gets.chomp
      @sock.puts(@client_protocol)
    end

    def get_kex_result(kex_init_raw = @kex_init_raw)
      @sock.write(kex_init_raw)
      resp = @sock.read(4)
      resp += @sock.read(resp.unpack("N").first)
      @sock.close

      kex_exchange_init = SSHScan::KeyExchangeInit.read(resp)

      # Assemble and print results
      result = {
        :ip => @ip,
        :port => @port,
        :server_banner => @server_protocol
      }
      result.merge!(kex_exchange_init.to_hash)

      return result
    end
  end
end
