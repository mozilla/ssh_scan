require 'spec_helper'
require 'rspec'
require 'ssh_scan/encryption_cipher'

describe SSHScan::EncryptionCipher do
  context "when initializing a cipher" do
    it "should create a cipher object (non-implementation specific)" do
      cipher = SSHScan::EncryptionCipher.new("curve25519-sha256")
      expect(cipher).to be_kind_of(SSHScan::EncryptionCipher)
      expect(cipher.to_s).to eql("curve25519-sha256")
      expect(cipher.base_cipher).to eql("curve25519-sha256")
    end

    it "should create a cipher object (implementation specific)" do
      cipher = SSHScan::EncryptionCipher.new("curve25519-sha256@foo.com")
      expect(cipher).to be_kind_of(SSHScan::EncryptionCipher)
      expect(cipher.to_s).to eql("curve25519-sha256@foo.com")
      expect(cipher.base_cipher).to eql("curve25519-sha256")
    end
  end

  context "when comparing cipher objects" do
    it "cipher obects from the same non-decriptive implementation should be equal" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha256")
      expect(cipher1).to eq(cipher2)
    end

    it "cipher obects from a non-decriptive implementation and a decriptive implementation should be equal" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha256@foo.com")
      expect(cipher1).to eq(cipher2)
    end

    it "cipher obects from same ciphers in two different decriptive implementations should be equal" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256@bar.com")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha256@foo.com")
      expect(cipher1).to eq(cipher2)
    end

    it "cipher obects from the different non-decriptive implementations should not be equal" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha1000")
      expect(cipher1).not_to eq(cipher2)
    end

    it "cipher obects from different non-decriptive implementation and a decriptive implementation should not be equal" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha1000@foo.com")
      expect(cipher1).not_to eq(cipher2)
    end

    it "cipher obects from same ciphers in two different decriptive implementations should be ==" do
      cipher1 = SSHScan::EncryptionCipher.new("curve25519-sha256@bar.com")
      cipher2 = SSHScan::EncryptionCipher.new("curve25519-sha1000@foo.com")
      expect(cipher1).not_to eq(cipher2)
    end
  end
end