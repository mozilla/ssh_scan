require 'ipaddr'
require 'resolv'
require 'timeout'

# Extend string to include some helpful stuff
class String
  def unhexify
    [self].pack("H*")
  end

  def hexify
    self.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
  end

  def ip_addr?
    begin
      IPAddr.new(self)

    # Using ArgumentError instead of IPAddr::InvalidAddressError
    # for 1.9.3 backward compatibility
    rescue ArgumentError
      return false
    end

    return true
  end

  def resolve_fqdn_as_ipv6(timeout = 3)
    begin
      Timeout::timeout(timeout) {
        Resolv::DNS.open do |dns|
          ress = dns.getresources self, Resolv::DNS::Resource::IN::AAAA
          temp = ress.map { |r| r.address  }
          return temp[0]
        end
      }
    rescue Timeout::Error
      return ""
    end
  end

  def resolve_fqdn_as_ipv4(timeout = 3)
    begin
      Timeout::timeout(timeout) {
        Resolv::DNS.open do |dns|
          ress = dns.getresources self, Resolv::DNS::Resource::IN::A
          temp = ress.map { |r| r.address  }
          return temp[0]
        end
      }
    rescue Timeout::Error
      return ""
    end

  end

  def resolve_fqdn
    TCPSocket.gethostbyname(self)[3]
  end

  def resolve_ptr(timeout = 3)
    begin
      Timeout::timeout(timeout) {
        reversed_dns = Resolv.new.getname(self)
        return reversed_dns
      }
    rescue Timeout::Error,Resolv::ResolvError
      return ""
    end
  end

  def fqdn?
    begin
      resolve_fqdn
    rescue SocketError, Timeout::Error
      return false
    end

    if ip_addr?
      return false
    else
      return true
    end
  end

end
