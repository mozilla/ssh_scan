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
        else
          return NetAddr::CIDR.create(ip).enumerate
        end
      end
    end
  end
end