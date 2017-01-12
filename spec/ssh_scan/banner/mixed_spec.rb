require 'spec_helper'
require 'rspec'
require_relative 'helper'

describe SSHScan::Banner do
  context "when fingerprinting (mixed examples)" do
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
      "SSH-2.0-ROSSSH" => {
        :os_class => SSHScan::OS::ROS,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::ROSSSH,
        :ssh_lib_version => "",
      },
    }
    checkFingerprints(fingerprint_expectations)
  end
end
