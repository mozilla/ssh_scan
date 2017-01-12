require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when windows fingerprinting" do
    expectations = {
      "SSH-2.0-OpenSSH_7.1p1 Microsoft_Win32_port_with_VS" => {
        :os_class => SSHScan::OS::Windows,
        :os_version => "",
        :ssh_lib_class => SSHScan::SSHLib::OpenSSH,
        :ssh_lib_version => "7.1p1",
      },
    }
    checkFingerprints(expectations)
  end
end
