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
    begin
      IPSocket.getaddress(self)
    rescue SocketError
      nil # Can return anything you want here
    end
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

  # Stolen from: https://github.com/emonti/rbkb/blob/master/lib/rbkb/extends/string.rb
  def hexify(opts={})
    delim = opts[:delim]
    pre = (opts[:prefix] || "")
    suf = (opts[:suffix] || "")

    if (rx=opts[:rx]) and not rx.kind_of? Regexp
      raise "rx must be a regular expression for a character class"
    end

    hx = [("0".."9").to_a, ("a".."f").to_a].flatten

    out=Array.new

    self.each_byte do |c|
      hc = if (rx and not rx.match c.chr)
             c.chr
           else
             pre + (hx[(c >> 4)] + hx[(c & 0xf )]) + suf
           end
      out << (hc)
    end
    out.join(delim)
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
