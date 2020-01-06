require 'netaddr'
require 'string_ext'

module SSHScan
  # Enumeration methods for IP notations.
  class TargetParser
    # Enumerate CIDR addresses, single IPs and IP ranges.
    # @param ip [String] IP address
    # @param port [Fixnum] port
    # @return [Array] array of enumerated addresses
    def enumerateIPRange(ip,port)
      port = 22 if port.nil?

      if ip.fqdn?
        socket = ip.concat(":").concat(port.to_s)
        return [socket]
      else
        if ip.include? "/"
          ip_net = nil

          # Attempt to parse as v4
          begin
            ip_net = NetAddr::IPv4Net.parse(ip)
          rescue ValidationError
            raise ArgumentError, "Invalid target: #{ip}"
          end

          sock_array = []
          1.upto(ip_net.len - 2) do |i|
            sock_array << ip_net.nth(i).to_s.concat(":" + port.to_s)
          end

          return sock_array
        else
          if port.nil?
            socket = ip
          else
            socket = ip.concat(":").concat(port.to_s)
          end
          return [socket]
        end
      end
    end
  end
end
