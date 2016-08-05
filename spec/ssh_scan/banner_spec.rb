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

  context "when OS guessing" do
    banner_legend = {
      "SSH-2.0-ubuntu" => SSHScan::OS::Ubuntu,
      "SSH-2.0-centos" => SSHScan::OS::CentOS,
      "SSH-2.0-debian" => SSHScan::OS::Debian,
      "SSH-2.0-freebsd" => SSHScan::OS::FreeBSD,
      "SSH-2.0-bananas" => SSHScan::OS::Unknown,
    }

    banner_legend.each do |banner_string, os_class|
      it "should detect the right OS for #{banner_string}" do
        banner = SSHScan::Banner.new(banner_string)
        expect(banner.os_guess).to be_kind_of(os_class)
      end
    end
  end

  context "when SSH library guessing" do
    banner_legend = {
      "SSH-2.0-openssh" => SSHScan::SSHLib::OpenSSH,
      "SSH-2.0-libssh" => SSHScan::SSHLib::LibSSH,
      "SSH-2.0-bananas" => SSHScan::SSHLib::Unknown,
    }

    banner_legend.each do |banner_string, ssh_lib_class|
      it "should detect the right OS for #{banner_string}" do
        banner = SSHScan::Banner.new(banner_string)
        expect(banner.ssh_lib_guess).to be_kind_of(ssh_lib_class)
      end
    end
  end

end
