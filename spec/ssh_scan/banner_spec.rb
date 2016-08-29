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
      "SSH-2.0-windows" => SSHScan::OS::Windows,
      "SSH-2.0-rhel" => SSHScan::OS::RedHat,
      "SSH-2.0-redhat" => SSHScan::OS::RedHat,
      "SSH-2.0-bananas" => SSHScan::OS::Unknown,
    }

    ubuntu_banner_legend = {
      "SSH-1.99-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.7" => "14.04",
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2" => "14.04",
      "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu1" => "16.04"
    }

    banner_legend.each do |banner_string, os_class|
      it "should detect the right OS for #{banner_string}" do
        banner = SSHScan::Banner.new(banner_string)
        expect(banner.os_guess).to be_kind_of(os_class)
      end
    end

    dummy_os = SSHScan::OS::Ubuntu.new("") # version = nil
    dummy_os.fingerprints.each do |ubuntu_version, banners|
      it "should not see duplicates in scraped fingerprints for Ubuntu #{ubuntu_version}" do
        expect(banners.uniq).to eql(banners)
      end
    end

    ubuntu_banner_legend.each do |banner_string, ubuntu_version|
      it "should detect correct Ubuntu version for \"#{banner_string}\"" do
        banner = SSHScan::Banner.new(banner_string)
        guessed_os = banner.os_guess
        expect(guessed_os).to be_kind_of(SSHScan::OS::Ubuntu)
        expect(guessed_os.ubuntu_version.to_s).to eql(ubuntu_version)
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

  context "when OpenSSH versioning" do
    banner_legend = {
      "SSH-2.0-OpenSSH_6.9p1 Debian-2" => {
        "ssh_lib_class" => SSHScan::SSHLib::OpenSSH,
        "version_class" => SSHScan::SSHLib::OpenSSH::Version,
        "version_string" => "6.9p1",
      },
      "SSH-2.0-OpenSSH_7.3" => {
        "ssh_lib_class" => SSHScan::SSHLib::OpenSSH,
        "version_class" => SSHScan::SSHLib::OpenSSH::Version,
        "version_string" => "7.3",
      },
      "SSH-2.0-OpenSSH_6.6.1p1-hpn14v2 FreeBSD-openssh-portable-6.6.p1_2,1" => {
        "ssh_lib_class" => SSHScan::SSHLib::OpenSSH,
        "version_class" => SSHScan::SSHLib::OpenSSH::Version,
        "version_string" => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH" => {
        "ssh_lib_class" => SSHScan::SSHLib::OpenSSH,
        "version_class" => NilClass,
        "version_string" => "",
      }
    }

    banner_legend.each do |banner_string, elements|
      it "should detect the right version for #{banner_string}" do
        banner = SSHScan::Banner.new(banner_string)
        expect(banner.ssh_lib_guess).to be_kind_of(elements["ssh_lib_class"])
        expect(banner.ssh_lib_guess.version).to be_kind_of(elements["version_class"])
        expect(banner.ssh_lib_guess.version.to_s).to eql(elements["version_string"])
      end
    end
  end

end
