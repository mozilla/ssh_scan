require 'socket'
require 'ssh_scan/constants'
require 'ssh_scan/protocol'
require 'ssh_scan/banner'
require 'ssh_scan/error'

module SSHScan
  class Client
    def initialize(ip, port, timeout = 3)
      @ip = ip
      @timeout = timeout

      @port = port.to_i
      @client_banner = SSHScan::Constants::DEFAULT_CLIENT_BANNER
      @server_banner = nil
      @kex_init_raw = SSHScan::Constants::DEFAULT_KEY_INIT.to_binary_s
    end

    def ip
      @ip
    end

    def port
      @port
    end

    def banner
      @server_banner
    end

    def close()
      begin
        unless @sock.nil?
          @sock.close
        end
      rescue
        @sock = nil
      end
      return true
    end

    def connect()
      @error = nil

      begin
        @sock = Socket.tcp(@ip, @port, connect_timeout: @timeout)
        @raw_server_banner = @sock.gets
      rescue SocketError => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::ETIMEDOUT => e
        @error = SSHScan::Error::ConnectTimeout.new(e.message)
        @sock = nil
      rescue Errno::ECONNREFUSED => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::ENETUNREACH => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
       rescue Errno::ECONNRESET => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::EACCES => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      rescue Errno::EHOSTUNREACH => e
        @error = SSHScan::Error::ConnectionRefused.new(e.message)
        @sock = nil
      else
        if @raw_server_banner.nil?
          @error = SSHScan::Error::NoBanner.new(
            "service did not respond with an SSH banner"
          )
          @sock = nil
        else
          @raw_server_banner = @raw_server_banner.chomp
          @server_banner = SSHScan::Banner.read(@raw_server_banner)
          @sock.puts(@client_banner.to_s)
        end
      end
    end

    def error?
      !@error.nil?
    end

    def error
      @error
    end

    def get_kex_result(kex_init_raw = @kex_init_raw)
      if !@sock
        @error = "Socket is no longer valid"
        return nil
      end

      begin
        @sock.write(kex_init_raw)
        resp = @sock.read(4)

        if resp.nil?
          @error = SSHScan::Error::NoKexResponse.new(
            "service did not respond to our kex init request"
          )
          @sock = nil
          return nil
        end

        resp += @sock.read(resp.unpack("N").first)
        @sock.close

        kex_exchange_init = SSHScan::KeyExchangeInit.read(resp)
      rescue Errno::ETIMEDOUT => e
        @error = SSHScan::Error::ConnectTimeout.new(e.message)
        @sock = nil
        return nil
      rescue Errno::ECONNREFUSED,
             Errno::ENETUNREACH,
             Errno::ECONNRESET,
             Errno::EACCES,
             Errno::EHOSTUNREACH
        @error = SSHScan::Error::NoKexResponse.new(
          "service did not respond to our kex init request"
        )
        @sock = nil
        return nil
      end

      return kex_exchange_init.to_hash
    end
  end
end
