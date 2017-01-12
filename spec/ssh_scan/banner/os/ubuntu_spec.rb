require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when ubuntu fingerprinting" do
    expectations = {
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
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "16.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.7" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.6" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.8" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.9p1",
      },
      "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.10" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.9p1",
      },
      "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.9p1",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "16.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.2p2",
      },
      "SSH-2.0-OpenSSH_6.6p1 Ubuntu-2ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6p1",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-8" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "14.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.6.1p1",
      },
      "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7.1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "10.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.3p1",
      },
      "SSH-2.0-OpenSSH_6.9p1 Ubuntu-2ubuntu0.2" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "15.10",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.9p1",
      },
      "SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "15.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
      "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.9" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_version => "12.04",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.9p1",
      },
      "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-9" => {
        :os_class => SSHScan::OS::Ubuntu,
        :os_cpe => "o:canonical:ubuntu",
      }
    }
    checkFingerprints(expectations)
  end
end
