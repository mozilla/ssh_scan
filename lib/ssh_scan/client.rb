require 'socket'
require 'ssh_scan/constants'
require 'ssh_scan/protocol'
require 'ssh_scan/banner'

module SSHScan
  class Client
    def initialize(target, port)
      @target = target

      if @target.ip_addr?
        @ip = @target
      else
        @ip = @target.resolve_fqdn()
      end

      @port = port
      @client_banner = SSHScan::Constants::DEFAULT_CLIENT_BANNER
      @server_banner = nil
      @kex_init_raw = SSHScan::Constants::DEFAULT_KEY_INIT_RAW
    end

    def connect()
      @sock = TCPSocket.new(@ip, @port)
      @raw_server_banner = @sock.gets.chomp
      @server_banner = SSHScan::Banner.read(@raw_server_banner)
      @sock.puts(@client_banner.to_s)
    end

    def get_kex_result(kex_init_raw = @kex_init_raw)
      @sock.write(kex_init_raw)
      resp = @sock.read(4)
      resp += @sock.read(resp.unpack("N").first)
      @sock.close

      kex_exchange_init = SSHScan::KeyExchangeInit.read(resp)

      # Assemble and print results
      result = {}
      result[:ssh_scan_version] = SSHScan::VERSION
      result[:hostname] = @target.fqdn? ? @target : ""
      result[:ip] = @ip
      result[:port] = @port
      result[:server_banner] = @server_banner
      result[:ssh_version] = @server_banner.ssh_version
      result[:os] = @server_banner.os_guess.common
      result[:os_cpe] = @server_banner.os_guess.cpe
      result[:ssh_lib] = @server_banner.ssh_lib_guess.common
      result[:ssh_lib_cpe] = @server_banner.ssh_lib_guess.cpe
      result.merge!(kex_exchange_init.to_hash)

      return result
    end
  end
end
