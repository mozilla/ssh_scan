require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when ipssh fingerprinting" do
    expectations = {
      "SSH-2.0-IPSSH-6.6.0" => {
        :ssh_lib_class => SSHScan::SSHLib::IpSsh,
        :ssh_lib_version => "6.6.0",
        :ssh_lib_cpe => "a:ipssh:ipssh:6.6.0",
      },
    }
    checkFingerprints(expectations)
  end
end
