require 'spec_helper'
require 'rspec'
require 'ssh_scan/ssh_fp'

describe SSHScan::SshFp do
  context "when querying for an SSHFP record" do
    it "should query the record and return fptype, algo, and hex" do
      fqdn = "myserverplace.de"
      sshfp = SSHScan::SshFp.new()
      expect(sshfp.query(fqdn)).to eq(
        [
         {"algo"=>"ecdsa",
          "fptype"=>"sha1",
          "hex"=>"7c:4b:9b:91:05:d6:a0:d7:aa:cf:44:53:4a:78:00:fc:10:46:66:83"},
         {"algo"=>"ecdsa",
          "fptype"=>"sha256",
          "hex"=>
          "cb:64:93:b1:0e:11:03:ff:1d:ba:b8:69:89:cf:a9:6f:a5:23:70:ac:33:ef:e6:d4:68:a5:f7:0b:8d:32:38:69"},
         {"algo"=>"ed25519",
          "fptype"=>"sha1",
          "hex"=>"69:ac:08:0c:cf:6c:d5:2f:47:88:37:3b:d4:dc:a2:17:31:e6:97:13"},
         {"algo"=>"ed25519",
          "fptype"=>"sha256",
          "hex"=>
           "7c:ae:4f:f9:42:89:9f:8e:15:5b:fc:67:5e:72:e4:14:6a:1b:f4:10:79:77:fe:73:c6:cf:fa:8f:3f:da:8f:c3"}
        ].sort_by { |k| k["hex"] }
      )
    end

    it "should query the record and return nil" do
      fqdn = "ssh.mozilla.com"
      sshfp = SSHScan::SshFp.new()
      expect(sshfp.query(fqdn)).to eq([])
    end
  end
end