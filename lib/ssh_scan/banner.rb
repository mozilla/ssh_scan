require 'ssh_scan/os'
require 'ssh_scan/ssh_lib'

module SSHScan
  class Banner
    def initialize(string)
      @string = string
    end

    # Create {SSHScan::Banner} object based on target's SSH banner.
    # @param string [String] String from which the banner should be
    #   constructed.
    # @return [SSHScan::Banner] {SSHScan::Banner} object
    #   constructed from string.
    def self.read(string)
      return SSHScan::Banner.new(string)
    end

    # Guess target's SSH version.
    # @return [String] If SSH version string looks like "SSH-1.81"
    #   or "SSH-number" then return the number, else return
    #   "unknown"
    def ssh_version()
      if match = @string.match(/SSH-(\d+[\.\d+]+)/)
        return match[1].to_f
      else
        return "unknown"
      end
    end

    # Guess target's SSH Library (OpenSSH, LibSSH ...).
    # See {SSHScan::SSHLib} for a list of SSH libraries supported.
    # @return [SSHScan::SSHLib] Guessed {SSHScan::SSHLib} instance,
    #   otherwise {SSHScan::SSHLib::Unknown} instance.
    def ssh_lib_guess()
      case @string
      when /OpenSSH/i
        return SSHScan::SSHLib::OpenSSH.new(@string)
      when /LibSSH/i
        return SSHScan::SSHLib::LibSSH.new()
      when /ipssh/i
        return SSHScan::SSHLib::IpSsh.new(@string)
      when /Cisco/i
        return SSHScan::SSHLib::CiscoSSH.new()
      when /ROS/
        return SSHScan::SSHLib::ROSSSH.new()
      when /DOPRASSH/i
        return SSHScan::SSHLib::DOPRASSH.new()
      when /cryptlib/i
        return SSHScan::SSHLib::Cryptlib.new()
      when /NOS-SSH/i
        return SSHScan::SSHLib::NosSSH.new(@string)
      when /pgp/i
        return SSHScan::SSHLib::PGP.new()
      when /ServerTech_SSH|Mocana SSH/i
        return SSHScan::SSHLib::SentrySSH.new()
      when /mpssh/i
        return SSHScan::SSHLib::Mpssh.new(@string)
      when /dropbear/i
        return SSHScan::SSHLib::Dropbear.new(@string)
      when /RomSShell/i
        return SSHScan::SSHLib::RomSShell.new(@string)
      when /Flowssh/i
        return SSHScan::SSHLib::FlowSsh.new(@string)
      else
        return SSHScan::SSHLib::Unknown.new()
      end
    end

    # Guess target's OS (Ubuntu, CentOS ...).
    # See {SSHScan::OS} for a list of OS(s) supported.
    # @return [SSHScan::OS] Guessed {SSHScan::OS} instance,
    #   otherwise {SSHScan::OS::Unknown} instance. 
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
      when /Windows|Microsoft/i
        return SSHScan::OS::Windows.new
      when /Cisco/i
        return SSHScan::OS::Cisco.new
      when /Raspbian/i
        return SSHScan::OS::Raspbian.new(@string)
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
