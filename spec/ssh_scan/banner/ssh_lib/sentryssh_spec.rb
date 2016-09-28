require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when sentryssh fingerprinting" do
    expectations = {
      "SSH-2.0-Mocana SSH" => {
        :ssh_lib_class => SSHScan::SSHLib::SentrySSH,
        :ssh_lib_version => "",
      },
      "SSH-2.0-ServerTech_SSH" => {
        :ssh_lib_class => SSHScan::SSHLib::SentrySSH,
        :ssh_lib_version => "",
      },
    }
    checkFingerprints(expectations)
  end
end
