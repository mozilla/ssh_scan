require 'spec_helper'
require 'rspec'
require 'ssh_scan/policy'
require 'tempfile'

describe SSHScan::Policy do
  context "when parsing a policy via YAML string" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n\
- diffie-hellman-group-exchange-sha256\n\
encryption:\n- aes256-ctr\n- aes192-ctr\n\
- aes128-ctr\nmacs:\n- hmac-sha2-512\n\
- hmac-sha2-256\ncompression:\n- none\n\
- zlib@openssh.com\n\
references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    it "should load all the attributes properly" do
      policy = SSHScan::Policy.from_string(yaml_string)

      expect(policy.name).to eql("Mozilla Intermediate")
      expect(policy.encryption).to eql(
        ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
      )
      expect(policy.kex).to eql(["diffie-hellman-group-exchange-sha256"])
      expect(policy.macs).to eql(["hmac-sha2-512", "hmac-sha2-256"])
      expect(policy.compression).to eql(["none", "zlib@openssh.com"])
      expect(policy.references).to eql(
        ["https://wiki.mozilla.org/Security/Guidelines/OpenSSH"]
      )
    end
  end

  context "when parsing a policy via YAML file" do
    yaml_string =
      "---\nname: Mozilla Intermediate\nkex:\n\
- diffie-hellman-group-exchange-sha256\n\
encryption:\n- aes256-ctr\n- aes192-ctr\n\
- aes128-ctr\nmacs:\n- hmac-sha2-512\n\
- hmac-sha2-256\ncompression:\n- none\n\
- zlib@openssh.com\n\
references:\n- https://wiki.mozilla.org/Security/Guidelines/OpenSSH\n"

    it "should load all the attributes properly" do
      file = Tempfile.new('foo')
      file.write(yaml_string)
      file.close

      policy = SSHScan::Policy.from_file(file.path)

      file.unlink

      expect(policy.name).to eql("Mozilla Intermediate")
      expect(policy.encryption).to eql(
        ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
      )
      expect(policy.kex).to eql(["diffie-hellman-group-exchange-sha256"])
      expect(policy.macs).to eql(["hmac-sha2-512", "hmac-sha2-256"])
      expect(policy.compression).to eql(["none", "zlib@openssh.com"])
      expect(policy.references).to eql(
        ["https://wiki.mozilla.org/Security/Guidelines/OpenSSH"]
      )
    end
  end

end
