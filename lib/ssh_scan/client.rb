require 'socket'
require 'ssh_scan/constants'
require 'ssh_scan/protocol'
require 'ssh_scan/banner'
require 'ssh_scan/error'

module SSHScan
  class Client
    def initialize(target, port, timeout = 3)
      @target = target
      @timeout = timeout

      @port = port
      @client_banner = SSHScan::Constants::DEFAULT_CLIENT_BANNER
      @server_banner = nil
      @kex_init_raw = SSHScan::Constants::DEFAULT_KEY_INIT.to_binary_s
    end

    def connect()
      begin
        @sock = Socket.tcp(@target, @port, connect_timeout: @timeout)
      rescue Errno::ETIMEDOUT => e
        @error = SSHScan::Error::ConnectTimeout.new(e.message)
        @sock = nil
      rescue Errno::ECONNREFUSED => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::ENETUNREACH => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::EACCES => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::EHOSTUNREACH => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      else
        @raw_server_banner = @sock.gets

        if @raw_server_banner.nil?
          @error = SSHScan::Error::NoBanner.new("service did not respond with an SSH banner")
          @sock = nil
        else
          @raw_server_banner = @raw_server_banner.chomp
          @server_banner = SSHScan::Banner.read(@raw_server_banner)
          @sock.puts(@client_banner.to_s)
        end
      end
    end

    def get_kex_result(kex_init_raw = @kex_init_raw)
      # Common options for all cases
      result = {}
      result[:ssh_scan_version] = SSHScan::VERSION
      result[:ip] = @target
      result[:port] = @port

      if !@sock
        result[:error] = @error
        return result
      end

      # Assemble and print results
      result[:server_banner] = @server_banner
      result[:ssh_version] = @server_banner.ssh_version
      result[:os] = @server_banner.os_guess.common
      result[:os_cpe] = @server_banner.os_guess.cpe
      result[:ssh_lib] = @server_banner.ssh_lib_guess.common
      result[:ssh_lib_cpe] = @server_banner.ssh_lib_guess.cpe

      @sock.write(kex_init_raw)
      resp = @sock.read(4)

      if resp.nil?
        @error = SSHScan::Error::NoKexResponse.new("service did not respond to our kex init request")
        @sock = nil
        return result
      end
      
      resp += @sock.read(resp.unpack("N").first)
      @sock.close

      kex_exchange_init = SSHScan::KeyExchangeInit.read(resp)
      result.merge!(kex_exchange_init.to_hash)

      return result
    end
  end
end
