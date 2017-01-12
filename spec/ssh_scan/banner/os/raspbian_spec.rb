require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when raspbian fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_6.7p1 Raspbian-5" => {
        :os_class => SSHScan::OS::Raspbian,
        # TODO fix me
        # :os_version => "5",
        :os_cpe => "o:raspbian:raspbian",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "6.7p1",
      },
    }
    checkFingerprints(expectations)
  end
end
