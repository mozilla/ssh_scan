require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when debian fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_7.3p1 Debian-1" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.3p1",
      },
      "SSH-2.0-OpenSSH_7.2p2 Debian-2" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
      "SSH-2.0-OpenSSH_7.2p2 Debian-5" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
      "SSH-2.0-OpenSSH_7.2p2 Debian-8" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
      "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
      "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
      "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4" => {
        :os_class => SSHScan::OS::Debian,
        :os_version => "",
        :os_cpe => "o:debian:debian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.0p1",
      },
    }
    checkFingerprints(expectations)
  end
end
