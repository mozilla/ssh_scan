require 'ssh_scan/os'
require 'ssh_scan/ssh_lib'

module SSHScan
  class Banner
    def initialize(string)
      @string = string
    end

    def self.read(string)
      return SSHScan::Banner.new(string)
    end

    def ssh_version()
      if version = @string.match(/SSH-(\d+[\.\d+]+)/)[1]
        return version.to_f
      else
        return "unknown"
      end
    end

    def ssh_lib_guess()
      case @string
      when /OpenSSH/i
        return SSHScan::SSHLib::OpenSSH.new(@string)
      when /LibSSH/i
        return SSHScan::SSHLib::LibSSH.new()
      when /Cisco/i
        return SSHScan::SSHLib::CiscoSSH.new()
      when /ROS/i
        return SSHScan::SSHLib::ROSSSH.new()
      when /DOPRASSH/i
        return SSHScan::SSHLib::DOPRASSH.new()
      else
        return SSHScan::SSHLib::Unknown.new()
      end
    end

    def os_guess()
      case @string
      when /Ubuntu/i
        return SSHScan::OS::Ubuntu.new(@string)
      when /6.6p1-5build1/i # non-standard Ubuntu release
        return SSHScan::OS::Ubuntu.new(@string)
      when /CentOS/i
        return SSHScan::OS::CentOS.new
      when /RHEL|RedHat/i
        return SSHScan::OS::RedHat.new
      when /FreeBSD/i
        return SSHScan::OS::FreeBSD.new
      when /Debian/i
        return SSHScan::OS::Debian.new
      when /Windows/i
        return SSHScan::OS::Windows.new
      when /Cisco/i
        return SSHScan::OS::Cisco.new
      when /ROS/i
        return SSHScan::OS::ROS.new
      when /DOPRA/i
        return SSHScan::OS::DOPRA.new
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
