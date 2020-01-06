require 'spec_helper'
require 'rspec'
require 'ssh_scan/target_parser'

describe SSHScan::TargetParser do
  context "FQDN without port" do
    it "should return an array containing that URL" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("github.com", nil)).to eq(
        ["github.com:22"]
      )
    end
  end

  context "FQDN with port" do
    it "should return an array containing that URL" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("github.com", 33)).to eq(
        ["github.com:33"]
      )
    end
  end

  context "IPv4 without port" do
    it "should return an array containing that IPv4" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("192.168.1.1", nil)).to eq(
        ["192.168.1.1:22"]
      )
    end
  end

  context "IPv4 with port" do
    it "should return an array containing that IPv4" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("192.168.1.1", 33)).to eq(
        ["192.168.1.1:33"]
      )
    end
  end

  context "IPv4 with subnet mask specified without port" do
    it "should return an array containing all the IPv4 in that range" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("192.168.1.0/30", nil)).to eq(
        ["192.168.1.1:22", "192.168.1.2:22"]
      )
    end
  end

  context "IPv4 with subnet mask specified with port" do
    it "should return an array containing all the IPv4 in that range" do
      target_parser = SSHScan::TargetParser.new()
      expect(target_parser.enumerateIPRange("192.168.1.0/30", 33)).to eq(
        ["192.168.1.1:33", "192.168.1.2:33"]
      )
    end
  end
end
