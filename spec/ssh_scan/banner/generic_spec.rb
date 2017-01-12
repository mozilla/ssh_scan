require 'spec_helper'
require 'rspec'
require_relative 'helper'

describe SSHScan::Banner do
  context "when fingerprinting (generic examples)" do
    expectations = {
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
      "SSH-2.0-rhel" => {
        :os_class => SSHScan::OS::RedHat,
      },
      "SSH-2.0-redhat" => {
        :os_class => SSHScan::OS::RedHat,
      },
      "SSH-2.0-cisco" => {
        :os_class => SSHScan::OS::Cisco,
      },
      "SSH-2.0-ros" => {
        :os_class => SSHScan::OS::ROS,
      },
      "SSH-1.99-DOPRA" => {
        :os_class => SSHScan::OS::DOPRA,
      },
      "SSH-2.0-bananas" => {
        :os_class => SSHScan::OS::Unknown,
      },
    }
    checkFingerprints(expectations)
  end
end
