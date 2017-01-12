require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when nosssh fingerprinting" do
    expectations = {
      "SSH-2.0-NOS-SSH_2.0" => {
        :ssh_lib_class => SSHScan::SSHLib::NosSSH,
        :ssh_lib_version => "2.0",
        :ssh_lib_cpe => "a:nosssh:nosssh:2.0",
      },
    }
    checkFingerprints(expectations)
  end
end
