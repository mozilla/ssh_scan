require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when raspbian fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_6.7p1 Raspbian-5" => {
        :os_class => SSHScan::OS::Raspbian,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
    }
    checkFingerprints(expectations)
  end
end
