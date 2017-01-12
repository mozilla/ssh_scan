require 'spec_helper'
require 'rspec'
require_relative 'helper'

describe SSHScan::Banner do
  context "when creating from scratch" do
    it "it should create a new Banner object" do
      banner_string = "SSH-2.0-server"
      banner = SSHScan::Banner.new(banner_string)
      expect(banner).to be_kind_of(SSHScan::Banner)
      expect(banner.to_s).to eql(banner_string)
    end
  end
end
