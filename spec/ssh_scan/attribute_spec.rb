require 'spec_helper'
require 'rspec'
require 'ssh_scan/attribute'

describe SSHScan::Attribute do

  context "when turning arrays into attribute arrays" do
    it "should create an array of attributes" do
      attribute_strings = ["foo", "bar", "baz"]

      SSHScan.make_attributes(attribute_strings).each do |attribute|
        expect(attribute).to be_kind_of(SSHScan::Attribute)
      end
    end

    it "should match on include? checks on exact match" do
      attribute_strings = ["foo", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("foo")
      expect(attribute_array.include?(attribute)).to be true
    end

    it "should match on include? checks on base match" do
      attribute_strings = ["foo", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("foo@foo.com")
      expect(attribute_array.include?(attribute)).to be true
    end

    it "should match on include? checks on reverse base match" do
      attribute_strings = ["foo@foo.com", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("foo")
      expect(attribute_array.include?(attribute)).to be true
    end

    it "should match on include? checks on different implmentation, but same base match" do
      attribute_strings = ["foo@foo.com", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("foo@baz.com")
      expect(attribute_array.include?(attribute)).to be true
    end

    it "should not match on include? checks" do
      attribute_strings = ["foo", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("abc")
      expect(attribute_array.include?(attribute)).to be false
    end

    it "should not match on include? checks on base" do
      attribute_strings = ["foo", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("abc@foo.com")
      expect(attribute_array.include?(attribute)).to be false
    end

    it "should not match on include? checks on reverse base" do
      attribute_strings = ["foo@foo.com", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("abc")
      expect(attribute_array.include?(attribute)).to be false
    end

    it "should not match on include? checks on different implmentation" do
      attribute_strings = ["foo@foo.com", "bar", "baz"]
      attribute_array = SSHScan.make_attributes(attribute_strings)
      attribute = SSHScan::Attribute.new("abc@baz.com")
      expect(attribute_array.include?(attribute)).to be false
    end
  end

  context "when initializing an attribute" do
    it "should create a attribute object (non-implementation specific)" do
      attribute = SSHScan::Attribute.new("curve25519-sha256")
      expect(attribute).to be_kind_of(SSHScan::Attribute)
      expect(attribute.to_s).to eql("curve25519-sha256")
      expect(attribute.base).to eql("curve25519-sha256")
    end

    it "should create a attribute (implementation specific)" do
      attribute = SSHScan::Attribute.new("curve25519-sha256@foo.com")
      expect(attribute).to be_kind_of(SSHScan::Attribute)
      expect(attribute.to_s).to eql("curve25519-sha256@foo.com")
      expect(attribute.base).to eql("curve25519-sha256")
    end
  end

  context "when comparing attribute objects" do
    it "cipher obects from the same non-decriptive implementation should be equal" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256")
      attribute2 = SSHScan::Attribute.new("curve25519-sha256")
      expect(attribute1).to eq(attribute2)
    end

    it "attribute objects from a non-decriptive implementation and a decriptive implementation should be equal" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256")
      attribute2 = SSHScan::Attribute.new("curve25519-sha256@foo.com")
      expect(attribute1).to eq(attribute2)
    end

    it "attribute objects from same ciphers in two different decriptive implementations should be equal" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256@bar.com")
      attribute2 = SSHScan::Attribute.new("curve25519-sha256@foo.com")
      expect(attribute1).to eq(attribute2)
    end

    it "attribute comparison from the different non-decriptive implementations should not be equal" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256")
      attribute2 = SSHScan::Attribute.new("curve25519-sha1000")
      expect(attribute1).not_to eq(attribute2)
    end

    it "attribute comparison from different non-decriptive implementation and a decriptive implementation should not be equal" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256")
      attribute2 = SSHScan::Attribute.new("curve25519-sha1000@foo.com")
      expect(attribute1).not_to eq(attribute2)
    end

    it "attribute comparison from same ciphers in two different decriptive implementations should be ==" do
      attribute1 = SSHScan::Attribute.new("curve25519-sha256@bar.com")
      attribute2 = SSHScan::Attribute.new("curve25519-sha1000@foo.com")
      expect(attribute1).not_to eq(attribute2)
    end
  end
end