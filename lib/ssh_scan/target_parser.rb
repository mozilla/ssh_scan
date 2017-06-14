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
      if ip.fqdn?
        if port.nil?
          socket = ip
        else
          socket = ip.concat(":").concat(port.to_s)
        end
        return [socket]
      else
        if ip.include? "-"
          octets = ip.split('.')
          range = octets.pop.split('-')
          lower = NetAddr::CIDR.create(octets.join('.') + "." + range[0])
          upper = NetAddr::CIDR.create(octets.join('.') + "." + range[1])
          ip_array = NetAddr.range(lower, upper,:Inclusive => true)
          if !port.nil?
            ip_array.map! { |i| i.concat(":").concat(port.to_s) }
          end
          return ip_array
        elsif ip.include? "/"
          begin
            cidr = NetAddr::CIDR.create(ip)
          rescue
            raise ArgumentError, "Invalid target: #{ip}"
          end
          ip_array = cidr.enumerate
          ip_array.delete(cidr.network)
          ip_array.delete(cidr.last)
          if !port.nil?
            ip_array.map! { |i| i.concat(":").concat(port.to_s) }
          end
          return ip_array
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
