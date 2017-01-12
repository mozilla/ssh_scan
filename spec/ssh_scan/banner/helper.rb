require 'spec_helper'
require 'rspec'
require 'ssh_scan/banner'

def checkFingerprints(fingerprint_expectations)
  fingerprint_expectations.each do |banner_string, expectations|
    it "should fingerprint #{banner_string} correctly" do
      banner = SSHScan::Banner.new(banner_string)

      if expectations[:os_class]
        expect(banner.os_guess).to be_kind_of(expectations[:os_class])
      end

      if expectations[:os_version]
        expect(banner.os_guess.version.to_s).to eql(
          expectations[:os_version]
        )
      end

      if expectations[:os_cpe]
        expect(banner.os_guess.cpe).to eql(expectations[:os_cpe])
      end

      if expectations[:ssh_lib_class]
        expect(banner.ssh_lib_guess).to be_kind_of(
          expectations[:ssh_lib_class]
        )
      end

      if expectations[:ssh_lib_version]
        expect(banner.ssh_lib_guess.version.to_s).to eql(
          expectations[:ssh_lib_version]
        )
      end

      if expectations[:ssh_lib_cpe]
        expect(banner.ssh_lib_guess.cpe).to eql(expectations[:ssh_lib_cpe])
      end
    end
  end
end
