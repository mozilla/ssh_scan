require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when flowssh fingerprinting" do
    expectations = {
      "SSH-2.0-5.32 FlowSsh" => {
        :ssh_lib_class => SSHScan::SSHLib::FlowSsh,
        :ssh_lib_version => "5.32",
        :ssh_lib_cpe => "a:bitvise:flowssh:5.32",
      },
    }
    checkFingerprints(expectations)
  end
end
