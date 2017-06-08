require 'spec_helper'
require 'rspec'
require 'ssh_scan/policy_manager'
require 'ssh_scan/policy'
require 'ssh_scan/result'
require 'ssh_scan/protocol'

describe SSHScan::PolicyManager do
  context "when checking out of policy encryption" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.encryption_algorithms_client_to_server = [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ]
    kex.encryption_algorithms_server_to_client = [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ]
    result.set_kex_result(kex)

    it "should have the right out of policy encryption" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result,policy)
      outliers = ["chacha20-poly1305@openssh.com",
                  "aes128-gcm@openssh.com",
                  "aes256-gcm@openssh.com"]
      expect(policy_manager.out_of_policy_encryption()).to eql(outliers)
    end
  end

  context "when checking the missing policy encryption" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.encryption_algorithms_client_to_server = [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ]
    kex.encryption_algorithms_server_to_client = [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ]
    result.set_kex_result(kex)

    it "should have the right missing policy encryption" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result,policy)
      outliers = []
      expect(policy_manager.missing_policy_encryption()).to eql(outliers)
    end
  end

  context "when checking out of policy mac" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.mac_algorithms_client_to_server = [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ]
    kex.mac_algorithms_server_to_client = [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ]
    result.set_kex_result(kex)

    it "should have the right out of policy macs" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result,policy)
      outliers = ["umac-64-etm@openssh.com",
                  "umac-128-etm@openssh.com",
                  "hmac-sha2-256-etm@openssh.com",
                  "hmac-sha2-512-etm@openssh.com",
                  "hmac-sha1-etm@openssh.com",
                  "umac-64@openssh.com",
                  "umac-128@openssh.com",
                  "hmac-sha1"]
      expect(policy_manager.out_of_policy_macs()).to eql(outliers)
    end
  end

  context "when checking the missing policy mac" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.mac_algorithms_client_to_server = [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ]
    kex.mac_algorithms_server_to_client = [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ]
    result.set_kex_result(kex)

    it "should have the right missing policy macs" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result,policy)
      outliers = []
      expect(policy_manager.missing_policy_macs()).to eql(outliers)
    end
  end

  context "when checking the allowed auth methods" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n"

    # Build up a test Result
    result = SSHScan::Result.new()
    result.auth_methods = [
      "publickey",
      "password",
    ]

    it "should have the right out of policy auth methods" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      outliers = ["password"]
      expect(policy_manager.out_of_policy_auth_methods()).to eql(outliers)
    end
  end

  context "when checking the minimum ssh_version" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\ncompression:\n- none\n" +
      "- zlib@openssh.com\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n" +
      "ssh_version: 2.0\n"

    # Build up a test Result
    result = SSHScan::Result.new()

    result.banner = SSHScan::Banner.new("SSH-1.9-server")

    it "should have the right out of policy ssh version" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.out_of_policy_ssh_version()).to eql(true)
    end
  end

  context "when checking compression on a policy that doesn't specify compression" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "encryption:\n- aes256-ctr\n- aes192-ctr\n" +
      "- aes128-ctr\nmacs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n" +
      "ssh_version: 2.0\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.compression_algorithms_client_to_server = [
      "none",
      "zlib",
      "zlib@openssh.com"
    ]
    kex.compression_algorithms_server_to_client = [
      "none",
      "zlib",
      "zlib@openssh.com"
    ]
    result.set_kex_result(kex)

    it "should not complain about compression" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.out_of_policy_compression).to eql([])
    end

    it "should not complain about compression" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.missing_policy_compression).to eql([])
    end
  end

  context "when checking encryption on a policy that doesn't specify encryption" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "macs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n" +
      "ssh_version: 2.0\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.encryption_algorithms_client_to_server = [
      "chacha20-poly1305@openssh.com",
      "aes256-ctr",
      "aes192-ctr",
      "aes128-ctr",
    ]
    kex.encryption_algorithms_server_to_client = [
      "chacha20-poly1305@openssh.com",
      "aes256-ctr",
      "aes192-ctr",
      "aes128-ctr",
    ]
    result.set_kex_result(kex)

    it "should not complain about encryption" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.missing_policy_encryption).to eql([])
    end
  end

  context "when checking macs on a policy that doesn't specify macs" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n" +
      "- diffie-hellman-group-exchange-sha256\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n" +
      "ssh_version: 2.0\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.mac_algorithms_client_to_server = [
      "hmac-sha1",
      "hmac-sha2-256",
      "hmac-sha2-512"
    ]
    kex.mac_algorithms_server_to_client = [
      "hmac-sha1",
      "hmac-sha2-256",
      "hmac-sha2-512"
    ]
    result.set_kex_result(kex)

    it "should not complain about macs" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.missing_policy_macs).to eql([])
    end
  end

  context "when checking macs on a policy that doesn't specify kex" do
    yaml_string =
      "---\nname: Mozilla Intermediate\n" +
      "macs:\n- hmac-sha2-512\n" +
      "- hmac-sha2-256\n" +
      "references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n" +
      "auth_methods:\n- publickey\n" +
      "ssh_version: 2.0\n"

    # Build up a Result based on a partial kex response
    result = SSHScan::Result.new()
    kex = SSHScan::KeyExchangeInit.new()
    kex.server_host_key_algorithms = [
      "ssh-dss",
      "ssh-rsa"
    ]
    result.set_kex_result(kex)

    it "should not complain about kex" do
      policy = SSHScan::Policy.from_string(yaml_string)
      policy_manager = SSHScan::PolicyManager.new(result, policy)
      expect(policy_manager.missing_policy_kex).to eql([])
    end
  end
end
