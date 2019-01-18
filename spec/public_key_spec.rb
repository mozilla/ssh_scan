require 'spec_helper'
require 'rspec'
require 'ssh_scan/public_key'

describe SSHScan::Crypto::PublicKey do
  context "when parsing an RSA key string" do
    it "should parse it and have the right values for each attribute" do
      key_string = "ssh-rsa " + 
                   "AAAAB3NzaC1yc2EAAAADAQABAAABAQCl/BNLUxR49+3AKqhf6sWKr" + 
                   "h8XXzqXV00bEPFtcJFWxyRqC5pPWo9zRRiS2jitIcqljIQVohEEZH" + 
                   "t48vZaA1hniVfe/FmrFzuCOuQOIP2fuRgLSNHu+lWVScsHoX/MuYX" + 
                   "EIxj6aW7UpFn4lD01mvPtazXFO/tJ+LRs49YBP7UvL1smIS2xoyuH" + 
                   "7kZDN17QG08YwbIB2fApMl8rXH+2Rpj5hlv+7rcZ1dqCGtmXmvsv8" + 
                   "fKGYd7BxRy0s/d7EY4e/DeDxA1qTNV9BrBTNn6jAKIedTE5s4GNRb" + 
                   "N/Q20mP2qmw70PiTGROw6xp9SBFA7N9hjjOT7iutK/pa7y1joXKjeJ"
      key = SSHScan::Crypto::PublicKey.new(key_string)
      expect(key).to be_kind_of SSHScan::Crypto::PublicKey
      expect(key.valid?).to be true
      expect(key.type).to eq("rsa")
      expect(key.length).to be 2048
      expect(key.fingerprint_md5).to eq("fc:c5:5b:0d:f0:c6:fd:fe:80:18:62:2c:05:38:20:8a")
      expect(key.fingerprint_sha1).to eq("e1:3c:71:49:80:37:87:32:b5:0c:e3:86:41:ef:2e:2a:2f:14:e3:58")
      expect(key.fingerprint_sha256).to eq("aH0wN2cs6x5Ktf9PvIzoQeFVqDBC4I484wq6vNv9XFA=")
      expect(key.to_hash).to eq(
        {
          "rsa" => {
            "fingerprints" => {
              "md5"=>"fc:c5:5b:0d:f0:c6:fd:fe:80:18:62:2c:05:38:20:8a",
              "sha1"=>"e1:3c:71:49:80:37:87:32:b5:0c:e3:86:41:ef:2e:2a:2f:14:e3:58",
              "sha256"=>"aH0wN2cs6x5Ktf9PvIzoQeFVqDBC4I484wq6vNv9XFA="
            },
            "length" => 2048,
            "raw" => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl/BNLUxR49+3AKqhf6sWKrh8XXzqXV00bEPFtcJFWxyRqC5pPWo9zRRiS2jitIcqljIQVohEEZHt48vZaA1hniVfe/FmrFzuCOuQOIP2fuRgLSNHu+lWVScsHoX/MuYXEIxj6aW7UpFn4lD01mvPtazXFO/tJ+LRs49YBP7UvL1smIS2xoyuH7kZDN17QG08YwbIB2fApMl8rXH+2Rpj5hlv+7rcZ1dqCGtmXmvsv8fKGYd7BxRy0s/d7EY4e/DeDxA1qTNV9BrBTNn6jAKIedTE5s4GNRbN/Q20mP2qmw70PiTGROw6xp9SBFA7N9hjjOT7iutK/pa7y1joXKjeJ",
          }
        }  
      )
    end
  end

  context "when parsing an DSA key string" do
    it "should parse it and have the right values for each attribute" do
      key_string = "ssh-dss " + 
                   "AAAAB3NzaC1kc3MAAACBAOXOC6kuB7xDMgHS79KFQITNeAT9tMKd2oK1" + 
                   "c6bQEHRgTSMP3sWZ1cntWVFKl5u6MEuEBBT9PZKWsy7vRE525Wwt+NbR" + 
                   "IBso3vYFF1MtxZKpAsF+gbGI7y+aZcIceXrHkkY2bz3oGb9I9MZ2DSu2" + 
                   "9crW11YHCmuOJ2FJiDcx7dV9AAAAFQC+Ws9e0KJaAsN8cj75DbTQumrd" + 
                   "JQAAAIBjn5EA5JvQg7xu8TRcNmZWhuyBLoOZczU6nk2h4i+x4pbpVMVr" + 
                   "Ch5Lr8wsH60w7IW4yKg6JvPlzmQW0ZRZAwnU9sC3YO64H1RFQg8tnmRr" + 
                   "w0I9oi6wKPEe5rLgbdr9jYHePs9tiV+ZFfUKmXh0s7srr/dwmX/gHCPI" + 
                   "whLEVa+dLQAAAIEAn/+dSyf6KXdfKNyx9MYc1l2/2YUhVuxClF26PNQX" + 
                   "0CZhcSoDyUXU/eAqaS7S6EYqtM/8FK1OZY1tzM5Nm4GWY2LLF22Q2YkK" + 
                   "ItkhfS3GaD5JeuTQ+HK0F+wQjmpqt2pUulVQXQAjvE1qoRFQ4/yeVrvh" +
                   "VqCzFICnariQP7tMYEo="
      key = SSHScan::Crypto::PublicKey.new(key_string)
      expect(key).to be_kind_of SSHScan::Crypto::PublicKey
      expect(key.valid?).to be true
      expect(key.type).to eq("dsa")
      expect(key.length).to be 1024
      expect(key.fingerprint_md5).to eq("6b:5f:8d:57:be:2e:55:7f:e3:d7:15:d1:66:17:d8:8c")
      expect(key.fingerprint_sha1).to eq("49:84:7f:d7:9d:84:2a:20:61:72:10:3f:2c:b1:16:9b:12:5b:e7:07")
      expect(key.fingerprint_sha256).to eq("sWZzgrGxzs/aMmcU2w6FyET/Iihd6HL1qNyDZnO0NDw=")
      expect(key.to_hash).to eq(
        {
          "dsa" => {
            "fingerprints" => {
              "md5"=>"6b:5f:8d:57:be:2e:55:7f:e3:d7:15:d1:66:17:d8:8c",
              "sha1"=>"49:84:7f:d7:9d:84:2a:20:61:72:10:3f:2c:b1:16:9b:12:5b:e7:07",
              "sha256"=>"sWZzgrGxzs/aMmcU2w6FyET/Iihd6HL1qNyDZnO0NDw="
            },
            "length" => 1024,
            "raw" => "ssh-dss AAAAB3NzaC1kc3MAAACBAOXOC6kuB7xDMgHS79KFQITNeAT9tMKd2oK1c6bQEHRgTSMP3sWZ1cntWVFKl5u6MEuEBBT9PZKWsy7vRE525Wwt+NbRIBso3vYFF1MtxZKpAsF+gbGI7y+aZcIceXrHkkY2bz3oGb9I9MZ2DSu29crW11YHCmuOJ2FJiDcx7dV9AAAAFQC+Ws9e0KJaAsN8cj75DbTQumrdJQAAAIBjn5EA5JvQg7xu8TRcNmZWhuyBLoOZczU6nk2h4i+x4pbpVMVrCh5Lr8wsH60w7IW4yKg6JvPlzmQW0ZRZAwnU9sC3YO64H1RFQg8tnmRrw0I9oi6wKPEe5rLgbdr9jYHePs9tiV+ZFfUKmXh0s7srr/dwmX/gHCPIwhLEVa+dLQAAAIEAn/+dSyf6KXdfKNyx9MYc1l2/2YUhVuxClF26PNQX0CZhcSoDyUXU/eAqaS7S6EYqtM/8FK1OZY1tzM5Nm4GWY2LLF22Q2YkKItkhfS3GaD5JeuTQ+HK0F+wQjmpqt2pUulVQXQAjvE1qoRFQ4/yeVrvhVqCzFICnariQP7tMYEo=",
          }
        }  
      )
    end
  end

end