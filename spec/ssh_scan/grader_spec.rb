require 'spec_helper'
require 'rspec'
require 'ssh_scan'

describe SSHScan::Grader do
  it "should provide an F grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
        "Add these Key Exchange Algos: ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256",
        "Add these MAC Algos: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com",
        "Add these Encryption Ciphers: aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "Remove these Key Exchange Algos: diffie-hellman-group14-sha1, diffie-hellman-group1-sha1",
        "Remove these MAC Algos: hmac-sha1",
        "Remove these Encryption Ciphers: aes256-cbc, aes192-cbc, aes128-cbc, blowfish-cbc",
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("F")
  end

  it "should provide an F grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
        "Add these Key Exchange Algos: ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256",
        "Add these MAC Algos: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com",
        "Add these Encryption Ciphers: aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "Remove these Key Exchange Algos: diffie-hellman-group14-sha1, diffie-hellman-group1-sha1",
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("F")
  end

  it "should provide an D grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
        "Add these Key Exchange Algos: ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256",
        "Add these MAC Algos: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com",
        "Add these Encryption Ciphers: aes256-gcm@openssh.com,aes128-gcm@openssh.com",
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("D")
  end

  it "should provide an C grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
        "Add these Key Exchange Algos: ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256",
        "Add these MAC Algos: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com",
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("C")
  end

  it "should provide an B grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
        "Add these Key Exchange Algos: ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256",
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("B")
  end

  it "should provide an A grade" do
    result = SSHScan::Result.new()
    result.set_compliance = {
      :policy => "Test Result",
      :compliant => false,
      :recommendations => [
      ]
    }
    grader = SSHScan::Grader.new(result)
    expect(grader.grade).to eql("A")
  end
end
