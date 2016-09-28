require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when pgp fingerprinting" do
    expectations = {
      "SSH-2.0-PGP" => {
        :ssh_lib_class => SSHScan::SSHLib::PGP,
        :ssh_lib_version => "",
      },
    }
    checkFingerprints(expectations)
  end
end
