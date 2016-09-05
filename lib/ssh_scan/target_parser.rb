require 'netaddr'
require 'string_ext'
require 'set'

module SSHScan
  class TargetParser
    def enumerateIPRange(ip, port = "22", port_append = false)
      if ip.fqdn?
        socket = port_append ? ip.concat(":").concat(port.to_s) : ip
        return [socket].to_set
      else
        if ip.include? "-"
          octets = ip.split('.')
          range = octets.pop.split('-')
          lower = NetAddr::CIDR.create(octets.join('.') + "." + range[0])
          upper = NetAddr::CIDR.create(octets.join('.') + "." + range[1])
          ip_array = NetAddr.range(lower, upper,:Inclusive => true)
          ip_array.map! { |ip| port_append ? ip.concat(":").concat(port.to_s) : ip }
          return ip_array.to_set
        elsif ip.include? "/"
          cidr = NetAddr::CIDR.create(ip)
          ip_array = cidr.enumerate
          ip_array.delete(cidr.network)
          ip_array.delete(cidr.last)
          ip_array.map! { |ip| port_append ? ip.concat(":").concat(port.to_s) : ip }
          return ip_array.to_set
        else
          socket = port_append ? ip.concat(":").concat(port.to_s) : ip
          return [socket].to_set
        end
      end
    end

    # Remove instances of ip, where ip:port already exist.
    # This would mean that port was somehow passed. Otherwise,
    # make ip = ip:22
    def sanitizeIPRange(ip_range)
      new_ip_range = ip_range.to_a
      ip_range.each do |old_ip|
        next if !old_ip.include?(':')
        ip_part = old_ip.split(':').first
        if old_ip.include?(':') and new_ip_range.include?(ip_part)
          new_ip_range.delete(ip_part)
        end
      end
      new_ip_range = new_ip_range.map { |ip| ip.include?(':') ? ip : ip + ":22" }
      return new_ip_range.to_set
    end
  end
end
