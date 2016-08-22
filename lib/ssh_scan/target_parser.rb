require 'netaddr'
require 'string_ext'

module SSHScan
  class TargetParser
    def enumerateIPRange(ip)
      if ip.fqdn?
        return [ip]
      else
        if ip.include? "-"
          octets = ip.split('.')
          range = octets.pop.split('-')
          lower = NetAddr::CIDR.create(octets.join('.') + "." + range[0])
          upper = NetAddr::CIDR.create(octets.join('.') + "." + range[1])
          ip_array = NetAddr.range(lower, upper,:Inclusive => true)
          return ip_array
        elsif ip.include? "/"
          cidr = NetAddr::CIDR.create(ip)
          ip_array = cidr.enumerate
          ip_array.delete(cidr.network)
          ip_array.delete(cidr.last)
          return ip_array
        else
          return [ip]
        end
      end
    end
  end
end