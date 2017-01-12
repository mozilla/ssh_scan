require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when mpssh fingerprinting" do
    expectations = {
      "SSH-2.0-mpSSH_0.2.1" => {
        :ssh_lib_class => SSHScan::SSHLib::Mpssh,
        :ssh_lib_version => "0.2.1",
        :ssh_lib_cpe => "a:mpssh:mpssh:0.2.1",
      },
    }
    checkFingerprints(expectations)
  end
end
