require 'ipaddr'

# Extend string to include some helpful stuff
class String
  def unhexify
    [self].pack("H*")
  end

  def ip_addr?
    begin
      IPAddr.new(self)
    rescue IPAddr::InvalidAddressError
      return false
    end

    return true
  end

  def resolve_fqdn
    @fqdn ||= TCPSocket.gethostbyname(self)[3]
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
