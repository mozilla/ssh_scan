require 'spec_helper'
require 'rspec'
require 'pathname'
require 'string_ext'
require 'resolv'

describe String do
  context "when unhexing a string" do
    testing_sample = "48656C6C6F20576F726C6421"
    it "should load all the attributes properly" do
      expected_unhexedstr = "Hello World!"
      test_result = testing_sample.unhexify
      expect(test_result).to eql(expected_unhexedstr)
    end
  end

  context "when hexing a string" do
  testing_sample = "Hello World!"
    it "should load all the attributes properly" do
      expected_hexedstr = "48656c6c6f20576f726c6421"
      test_result = testing_sample.hexify
      expect(test_result).to eql(expected_hexedstr)
    end
  end

  context "when verifying an IP address" do
  testing_target = "127.0.0.1"
    it "should load all the attributes properly" do
      test_result = testing_target.ip_addr?
      expect(test_result).to eql(true)
    end
  end

  context "when resolving a DNS name as IPv4" do
  testing_dns = "github.com"
    it "should load all the attributes properly" do
      test_result = testing_dns.resolve_fqdn_as_ipv4.to_s
      expect(test_result).to match(Resolv::IPv4::Regex256)
    end
  end

  context "when resolving a DNS name into IP address" do
  testing_host = "localhost"
    it "should load all the attributes properly" do
      expected_result = /^::1$|^127.0.0.1$/
      test_result = testing_host.resolve_fqdn
      expect(test_result).to match(expected_result)
    end
  end

  context "when verifying a DNS name and IP address" do
  testing_dns = "google.com"
    it "should load all the attributes properly" do
      test_result = testing_dns.fqdn?
      expect(test_result).to eql(true)
    end
  end

end