require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when freebsd fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_5.4p1 FreeBSD-20100308" => {
        :os_class => SSHScan::OS::FreeBSD,
        :os_version => "",
        :os_cpe => "o:freebsd:freebsd",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "5.4p1",
      },
    }
    checkFingerprints(expectations)
  end
end
