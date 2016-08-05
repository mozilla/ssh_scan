require 'ssh_scan/os'
require 'ssh_scan/ssh_lib'

module SSHScan
  class Banner
    def initialize(string)
      @string = string
    end

    def self.read(string)
      return SSHScan::Banner.new(string.chomp)
    end

    def ssh_lib_guess()
      case @string
      when /OpenSSH/i
        return SSHScan::SSHLib::OpenSSH.new()
      when /LibSSH/i
        return SSHScan::SSHLib::LibSSH.new()
      else
        return SSHScan::SSHLib::Unknown.new()
      end
    end

    def os_guess()
      case @string
      when /Ubuntu/i
        return SSHScan::OS::Ubuntu.new
      when /CentOS/i
        return SSHScan::OS::CentOS.new
      when /FreeBSD/i
        return SSHScan::OS::FreeBSD.new
      when /Debian/i
        return SSHScan::OS::Debian.new
      else
        return SSHScan::OS::Unknown.new
      end
    end

    def ==(other)
      self.to_s == other.to_s
    end

    def to_s
      @string
    end
  end
end
