require 'rspec'
require 'ssh_scan/crypto'

describe SSHScan::Crypto::PublicKey do
  context "when generating fingerprints" do
    it "should generate fingerprints for RSA correctly" do
      n = 23632077324088144501092249680419323739801323600158813273568324482496307162318789721613792811401614942684260029660183874482776189498160448960310809637920685817778474704815582955313091633951038693905769728720185981622436072311236535004735349701960456244504965079638695753583677574707979833350935481548040866639919163639882690698478860068170762157813993121946939288799580004748275380656448478194991959145948158111224324849043207283358199193762047855464042037676265770354633294836412162886761428400000041644966377946401322325086274306679173170324632010743865598861975638899651525149666813619204319259532409320007544358571
      e = 65537
      md5_expected = "82:13:2b:db:4d:5e:2d:e2:1b:b3:2b:25:eb:0b:9a:ed"
      sha1_expected = "19:42:84:7a:b3:5c:1b:85:ee:81:9f:a8:19:e2:64:dc:44:81:a2:61"
      sha256_expected = "ae:fb:8b:a2:e3:89:23:d2:12:fb:75:49:24:ed:f0:50:07:5f:c9:76:2c:14:ee:51:ae:96:e4:85:1d:6d:e7:79"
      publickey = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Integer.new(n),
        OpenSSL::ASN1::Integer.new(e)
      ])
      sequence = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new("rsaEncryption"),
          OpenSSL::ASN1::Null.new(nil)
        ]),
        OpenSSL::ASN1::BitString.new(publickey.to_der)
      ])
      key = OpenSSL::PKey::RSA.new(sequence.to_der)
      host_key = SSHScan::Crypto::PublicKey.new(key)
      expect(host_key.is_supported?).to eql(true)
      expect(host_key.fingerprint_md5).to eql(md5_expected)
      expect(host_key.fingerprint_sha1).to eql(sha1_expected)
      expect(host_key.fingerprint_sha256).to eql(sha256_expected)
    end
  end
end
