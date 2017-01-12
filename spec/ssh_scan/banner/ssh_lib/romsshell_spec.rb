require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when romsshell fingerprinting" do
    expectations = {
      "SSH-2.0-RomSShell_4.62" => {
        :ssh_lib_class => SSHScan::SSHLib::RomSShell,
        :ssh_lib_version => "4.62",
        :ssh_lib_cpe => "a:allegrosoft:romsshell:4.62",
      },
    }
    checkFingerprints(expectations)
  end
end
