require 'rspec'
require 'protocol'

describe SSH::KeyExchangeInit do
  context "when parsing raw client SSH Key Exchange Initialization messages on the wire" do
    raw_kex_client_init = ("000001640414e33f813f8cdcc6b00a3d852ec1aea4980000001a6" +
                            "469666669652d68656c6c6d616e2d67726f7570312d7368613100" +
                            "00000f7373682d6473732c7373682d72736100000057616573313" +
                            "2382d6362632c336465732d6362632c626c6f77666973682d6362" +
                            "632c6165733139322d6362632c6165733235362d6362632c61657" +
                            "33132382d6374722c6165733139322d6374722c6165733235362d" +
                            "637472000000576165733132382d6362632c336465732d6362632" +
                            "c626c6f77666973682d6362632c6165733139322d6362632c6165" +
                            "733235362d6362632c6165733132382d6374722c6165733139322" +
                            "d6374722c6165733235362d63747200000021686d61632d6d6435" +
                            "2c686d61632d736861312c686d61632d726970656d64313630000" +
                            "00021686d61632d6d64352c686d61632d736861312c686d61632d" +
                            "726970656d64313630000000046e6f6e65000000046e6f6e65000" +
                            "000000000000000000000006e05b3b4").unhexify
    kex_init = SSH::KeyExchangeInit.read(raw_kex_client_init)

    it "should properly parse a raw client KeyExchangeInit from the wire" do
      # Attribute values
      expect(kex_init.packet_length).to eql(356)
      expect(kex_init.padding_length).to eql(4)
      expect(kex_init.message_code).to eql(20)
      expect(kex_init.cookie).to eql("e33f813f8cdcc6b00a3d852ec1aea498".unhexify)
      expect(kex_init.kex_algorithms_length).to eql(26)
      expect(kex_init.key_algorithms_string).to eql("diffie-hellman-group1-sha1")
      expect(kex_init.server_host_key_algorithms_length).to eql(15)
      expect(kex_init.server_host_key_algorithms_string).to eql("ssh-dss,ssh-rsa")
      expect(kex_init.encryption_algorithms_client_to_server_length).to eql(87)
      expect(kex_init.encryption_algorithms_client_to_server_string).to eql(
        "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr"
      )
      expect(kex_init.encryption_algorithms_server_to_client_length).to eql(87)
      expect(kex_init.encryption_algorithms_server_to_client_string).to eql(
        "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr"
      )
      expect(kex_init.mac_algorithms_client_to_server_length).to eql(33)
      expect(kex_init.mac_algorithms_client_to_server_string).to eql(
        "hmac-md5,hmac-sha1,hmac-ripemd160"
      )
      expect(kex_init.compression_algorithms_client_to_server_length).to eql(4)
      expect(kex_init.compression_algorithms_client_to_server_string).to eql("none")
      expect(kex_init.compression_algorithms_server_to_client_length).to eql(4)
      expect(kex_init.compression_algorithms_server_to_client_string).to eql("none")
      expect(kex_init.languages_client_to_server_length).to eql(0)
      expect(kex_init.languages_client_to_server_string).to eql("")
      expect(kex_init.languages_server_to_client_length).to eql(0)
      expect(kex_init.languages_server_to_client_string).to eql("")
      expect(kex_init.kex_first_packet_follows).to eql(0)
      expect(kex_init.reserved).to eql(0)

      # Instance methods (lets do stuff)
      expect(kex_init.key_algorithms).to eql(["diffie-hellman-group1-sha1"])
      expect(kex_init.server_host_key_algorithms).to eql(["ssh-dss","ssh-rsa"])
      expect(kex_init.encryption_algorithms_client_to_server).to eql(
        ["aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc","aes128-ctr","aes192-ctr","aes256-ctr"]
      )
      expect(kex_init.encryption_algorithms_server_to_client).to eql(
        ["aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc","aes128-ctr","aes192-ctr","aes256-ctr"]
      )
      expect(kex_init.mac_algorithms_client_to_server).to eql(["hmac-md5","hmac-sha1","hmac-ripemd160"])
      expect(kex_init.mac_algorithms_server_to_client).to eql(["hmac-md5","hmac-sha1","hmac-ripemd160"])
      expect(kex_init.compression_algorithms_client_to_server).to eql(["none"])
      expect(kex_init.compression_algorithms_server_to_client).to eql(["none"])
      expect(kex_init.languages_client_to_server).to eql([])
      expect(kex_init.languages_server_to_client).to eql([])

      # Summarize the structure elements to hash and json
      expect(kex_init.to_hash).to eql(
        {:key_algorithms => ["diffie-hellman-group1-sha1"],
         :server_host_key_algorithms => ["ssh-dss", "ssh-rsa"],
         :encryption_algorithms_client_to_server => [
           "aes128-cbc", "3des-cbc", "blowfish-cbc", "aes192-cbc", "aes256-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr"
          ],
         :encryption_algorithms_server_to_client => [
           "aes128-cbc", "3des-cbc", "blowfish-cbc", "aes192-cbc", "aes256-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr"
          ],
         :mac_algorithms_client_to_server => [
           "hmac-md5", "hmac-sha1", "hmac-ripemd160"
          ],
         :mac_algorithms_server_to_client => [
           "hmac-md5", "hmac-sha1", "hmac-ripemd160"
          ],
         :compression_algorithms_client_to_server=>["none"],
         :compression_algorithms_server_to_client => ["none"],
         :languages_client_to_server=>[],
         :languages_server_to_client=>[]
         }
      )
      expect(kex_init.to_json).to eql(
        '{"key_algorithms":["diffie-hellman-group1-sha1"],"server_host_key_algorithms":["ssh-dss","ssh-rsa"],"encryption_algorithms_client_to_server":["aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc","aes128-ctr","aes192-ctr","aes256-ctr"],"encryption_algorithms_server_to_client":["aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc","aes128-ctr","aes192-ctr","aes256-ctr"],"mac_algorithms_client_to_server":["hmac-md5","hmac-sha1","hmac-ripemd160"],"mac_algorithms_server_to_client":["hmac-md5","hmac-sha1","hmac-ripemd160"],"compression_algorithms_client_to_server":["none"],"compression_algorithms_server_to_client":["none"],"languages_client_to_server":[],"languages_server_to_client":[]}'
      )
    end
  end

  context "when parsing raw server SSH Key Exchange Initialization messages on the wire" do
    raw_server_kex_init = ("000003440a140a39a3ff9c1923dcb2ba9e641bbc7feb0000007e646" +
                           "9666669652d68656c6c6d616e2d67726f75702d65786368616e6765" +
                           "2d7368613235362c6469666669652d68656c6c6d616e2d67726f757" +
                           "02d65786368616e67652d736861312c6469666669652d68656c6c6d" +
                           "616e2d67726f757031342d736861312c6469666669652d68656c6c6" +
                           "d616e2d67726f7570312d736861310000000f7373682d7273612c73" +
                           "73682d6473730000009d6165733132382d6374722c6165733139322" +
                           "d6374722c6165733235362d6374722c617263666f75723235362c61" +
                           "7263666f75723132382c6165733132382d6362632c336465732d636" +
                           "2632c626c6f77666973682d6362632c636173743132382d6362632c" +
                           "6165733139322d6362632c6165733235362d6362632c617263666f7" +
                           "5722c72696a6e6461656c2d636263406c797361746f722e6c69752e" +
                           "73650000009d6165733132382d6374722c6165733139322d6374722" +
                           "c6165733235362d6374722c617263666f75723235362c617263666f" +
                           "75723132382c6165733132382d6362632c336465732d6362632c626" +
                           "c6f77666973682d6362632c636173743132382d6362632c61657331" +
                           "39322d6362632c6165733235362d6362632c617263666f75722c726" +
                           "96a6e6461656c2d636263406c797361746f722e6c69752e73650000" +
                           "0085686d61632d6d64352c686d61632d736861312c756d61632d363" +
                           "4406f70656e7373682e636f6d2c686d61632d736861322d3235362c" +
                           "686d61632d736861322d3531322c686d61632d726970656d6431363" +
                           "02c686d61632d726970656d64313630406f70656e7373682e636f6d" +
                           "2c686d61632d736861312d39362c686d61632d6d64352d393600000" +
                           "085686d61632d6d64352c686d61632d736861312c756d61632d3634" +
                           "406f70656e7373682e636f6d2c686d61632d736861322d3235362c6" +
                           "86d61632d736861322d3531322c686d61632d726970656d64313630" +
                           "2c686d61632d726970656d64313630406f70656e7373682e636f6d2" +
                           "c686d61632d736861312d39362c686d61632d6d64352d3936000000" +
                           "156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6" +
                           "f6e652c7a6c6962406f70656e7373682e636f6d0000000000000000" +
                           "000000000000000000000000000000").unhexify
    kex_init = SSH::KeyExchangeInit.read(raw_server_kex_init)

    it "should properly parse a raw server KeyExchangeInit from the wire" do
      expect(kex_init.packet_length).to eql(836)
      expect(kex_init.padding_length).to eql(10)
      expect(kex_init.message_code).to eql(20)
      expect(kex_init.cookie).to eql("0a39a3ff9c1923dcb2ba9e641bbc7feb".unhexify)
      expect(kex_init.kex_algorithms_length).to eql(126)
      expect(kex_init.key_algorithms_string).to eql("diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
      expect(kex_init.server_host_key_algorithms_length).to eql(15)
      expect(kex_init.server_host_key_algorithms_string).to eql("ssh-rsa,ssh-dss")
      expect(kex_init.encryption_algorithms_client_to_server_length).to eql(157)
      expect(kex_init.encryption_algorithms_client_to_server_string).to eql(
        "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se"
      )
      expect(kex_init.encryption_algorithms_server_to_client_length).to eql(157)
      expect(kex_init.encryption_algorithms_server_to_client_string).to eql(
        "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se"
      )
      expect(kex_init.mac_algorithms_client_to_server_length).to eql(133)
      expect(kex_init.mac_algorithms_client_to_server_string).to eql(
        "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96"
      )
      expect(kex_init.compression_algorithms_client_to_server_length).to eql(21)
      expect(kex_init.compression_algorithms_client_to_server_string).to eql("none,zlib@openssh.com")
      expect(kex_init.compression_algorithms_server_to_client_length).to eql(21)
      expect(kex_init.compression_algorithms_server_to_client_string).to eql("none,zlib@openssh.com")
      expect(kex_init.languages_client_to_server_length).to eql(0)
      expect(kex_init.languages_client_to_server_string).to eql("")
      expect(kex_init.languages_server_to_client_length).to eql(0)
      expect(kex_init.languages_server_to_client_string).to eql("")
      expect(kex_init.kex_first_packet_follows).to eql(0)
      expect(kex_init.reserved).to eql(0)

      # Instance methods (lets do stuff)
      expect(kex_init.key_algorithms).to eql(
        ["diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]
      )
      expect(kex_init.server_host_key_algorithms).to eql(["ssh-rsa", "ssh-dss"])
      expect(kex_init.encryption_algorithms_client_to_server).to eql(
        ["aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "rijndael-cbc@lysator.liu.se"]
      )
      expect(kex_init.encryption_algorithms_server_to_client).to eql(
        ["aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "rijndael-cbc@lysator.liu.se"]
      )
      expect(kex_init.mac_algorithms_client_to_server).to eql(
        ["hmac-md5", "hmac-sha1", "umac-64@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-sha1-96", "hmac-md5-96"]
      )
      expect(kex_init.mac_algorithms_server_to_client).to eql(
        ["hmac-md5", "hmac-sha1", "umac-64@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-sha1-96", "hmac-md5-96"]
      )
      expect(kex_init.compression_algorithms_client_to_server).to eql(["none", "zlib@openssh.com"])

      # BUG: causes stack level too deep error (no idea why)
      #expect(kex_init.compression_algorithms_server_to_client).to eql(["none"])

      expect(kex_init.languages_client_to_server).to eql([])
      expect(kex_init.languages_server_to_client).to eql([])
    end
  end

end
