require 'rspec'
require 'ssh_scan/banner'

describe SSHScan::Banner do
  context "when creating from scratch" do
    it "it should create a new Banner object" do
      banner_string = "SSH-2.0-server"
      banner = SSHScan::Banner.new(banner_string)
      expect(banner).to be_kind_of(SSHScan::Banner)
      expect(banner.to_s).to eql(banner_string)
    end
  end

  context "when fingerprinting" do
    fingerprint_expectations = {
      "SSH-1.99-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.7" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_6.9p1 Debian-2" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.9p1",
      },
      "SSH-2.0-OpenSSH_7.3" => {
        :os_class => SSHScan::OS::Unknown,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.3",
      },
      "SSH-2.0-OpenSSH_6.6.1p1-hpn14v2 FreeBSD-openssh-portable-6.6.p1_2,1" => {
        :os_class => SSHScan::OS::FreeBSD,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-Cisco-1.25" => {
        :os_class => SSHScan::OS::Cisco,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::CiscoSSH,
        :ssh_lib_version => "",
      },

      # Generic Examples
      "SSH-2.0-OpenSSH" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
      },
      "SSH-2.0-ubuntu" => {
        :os_class => SSHScan::OS::Ubuntu,
      },
      "SSH-2.0-centos" => {
        :os_class => SSHScan::OS::CentOS,
      },
      "SSH-2.0-debian" => {
        :os_class => SSHScan::OS::Debian,
      },
      "SSH-2.0-freebsd" => {
        :os_class => SSHScan::OS::FreeBSD,
      },
      "SSH-2.0-windows" => {
        :os_class => SSHScan::OS::Windows,
      },
      "SSH-2.0-windows" => {
        :os_class => SSHScan::OS::Windows,
      },
      "SSH-2.0-rhel" => {
        :os_class => SSHScan::OS::RedHat,
      },
      "SSH-2.0-redhat" => {
        :os_class => SSHScan::OS::RedHat,
      },
      "SSH-2.0-cisco" => {
        :os_class => SSHScan::OS::Cisco,
      },
      "SSH-2.0-bananas" => {
        :os_class => SSHScan::OS::Unknown,
      },

      # Ubuntu major-version Examples
      "SSH-2.0-OpenSSH_3.8.1p1-11ubuntu3.3" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "4.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "3.8.1p1",
      },
      "SSH-2.0-OpenSSH_3.9p1-1ubuntu2.3" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "5.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "3.9p1",
      },
      "SSH-2.0-OpenSSH_4.1p1-7ubuntu4.2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "5.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "4.1p1",
      },
      "SSH-2.0-OpenSSH_4.2p1-7ubuntu3.5" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "6.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "4.2p1",
      },
      "SSH-2.0-OpenSSH_4.3p2-5ubuntu1.2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "6.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "4.3p2",
      },
      "SSH-2.0-OpenSSH_4.6p1-5ubuntu0.6" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "7.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "4.6p1",
      },
      "SSH-2.0-OpenSSH_4.7p1-8ubuntu3" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "8.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "4.7p1",
      },
      "SSH-2.0-OpenSSH_5.1p1-3ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "8.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.1p1",
      },
      "SSH-2.0-OpenSSH_5.1p1-5ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "9.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.1p1",
      },
      "SSH-2.0-OpenSSH_5.1p1-6ubuntu2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "9.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.1p1",
      },
      "SSH-2.0-OpenSSH_5.3p1-3ubuntu7.1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "10.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.3p1",
      },
      "SSH-2.0-OpenSSH_5.5p1-4ubuntu6" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "10.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.5p1",
      },
      "SSH-2.0-OpenSSH_5.8p1-1ubuntu3" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "11.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.8p1",
      },
      "SSH-2.0-OpenSSH_5.8p1-7ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "11.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.8p1",
      },
      "SSH-2.0-OpenSSH_5.9p1-5ubuntu1.10" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.9p1",
      },
      "SSH-2.0-OpenSSH_6.0p1-3ubuntu1.2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.0p1",
      },
      "SSH-2.0-OpenSSH_6.1p1-1ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "13.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.1p1",
      },
      "SSH-2.0-OpenSSH_6.2p2-6ubuntu0.5" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "13.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.2p2",
      },
      "SSH-2.0-OpenSSH_6.6p1-2ubuntu2.8" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6p1",
      },
      "SSH-2.0-OpenSSH_6.6p1-5build1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6p1",
      },
      "SSH-2.0-OpenSSH_6.7p1-5ubuntu1.4" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "15.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
      "SSH-2.0-OpenSSH_6.9p1-2ubuntu0.2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "15.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.9p1",
      },
      "SSH-2.0-OpenSSH_7.2p2-4ubuntu2.1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "16.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
    }

    fingerprint_expectations.each do |banner_string, expectations|
      it "should fingerprint #{banner_string} correctly" do
        banner = SSHScan::Banner.new(banner_string)

        if expectations[:os_class]
          expect(banner.os_guess).to be_kind_of(expectations[:os_class])
        end

        if expectations[:os_version]
          expect(banner.os_guess.version.to_s).to eql(expectations[:os_version])
        end

        if expectations[:ssh_lib_class]
          expect(banner.ssh_lib_guess).to be_kind_of(expectations[:ssh_lib_class])
        end

        if expectations[:ssh_lib_version]
          expect(banner.ssh_lib_guess.version.to_s).to eql(expectations[:ssh_lib_version])
        end
      end
    end
  end
end
