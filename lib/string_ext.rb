require 'ipaddr'
require 'netaddr'

# Extend string to include some helpful stuff
class String
  def unhexify
    [self].pack("H*")
  end

  def ip_addr?
    begin
      IPAddr.new(self)

    # Using ArgumentError instead of IPAddr::InvalidAddressError for 1.9.3 backward compatability
    rescue ArgumentError
      return false
    end

    return true
  end

  def resolve_fqdn
    @fqdn ||= TCPSocket.gethostbyname(self)[3]
  end

  def resolve_ip
    ip_ranges = self.split('-')
    lower = NetAddr::CIDR.create(ip_ranges[0])
    temp = ip_ranges[0].split('.')
    temp[3] = ip_ranges[1]
    upper = NetAddr::CIDR.create(temp.join("."))
    ip_ranges = NetAddr.range(lower, upper,:Inclusive => true)
    return ip_ranges
  end

  def fqdn?
    begin
      resolve_fqdn
    rescue SocketError
      return false
    end

    if ip_addr?
      return false
    else
      return true
    end
  end

end
