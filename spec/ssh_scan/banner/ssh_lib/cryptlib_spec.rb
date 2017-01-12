require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when cryptlib fingerprinting" do
    expectations = {
      "SSH-2.0-cryptlib" => {
        :ssh_lib_class => SSHScan::SSHLib::Cryptlib,
        :ssh_lib_version => "",
        :ssh_lib_cpe => "a:cryptlib:cryptlib",
      },
    }
    checkFingerprints(expectations)
  end
end
