require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when pgp fingerprinting" do
    expectations = {
      "SSH-2.0-PGP" => {
        :ssh_lib_class => SSHScan::SSHLib::PGP,
        :ssh_lib_version => "",
        :ssh_lib_cpe => "a:pgp:pgp",
      },
    }
    checkFingerprints(expectations)
  end
end
