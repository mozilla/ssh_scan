require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when openssh fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_7.3" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.3",
        :ssh_lib_cpe => "a:openssh:openssh:7.3",
      },
      "SSH-2.0-OpenSSH_6.8p1-hpn14v6" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.8p1",
        :ssh_lib_cpe => "a:openssh:openssh:6.8p1",
      },
      "SSH-2.0-OpenSSH_6.6.1" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1",
        :ssh_lib_cpe => "a:openssh:openssh:6.6.1",
      },
      "SSH-2.0-OpenSSH_6.2 FIPS" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.2",
        :ssh_lib_cpe => "a:openssh:openssh:6.2",
      },
      "SSH-2.0-OpenSSH_12.1" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "12.1",
        :ssh_lib_cpe => "a:openssh:openssh:12.1",
      },
      "SSH-1.99-OpenSSH_3.7.1p2" => {
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "3.7.1p2",
        :ssh_lib_cpe => "a:openssh:openssh:3.7.1p2",
      },
    }
    checkFingerprints(expectations)
  end
end
