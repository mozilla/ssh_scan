require 'rspec'
require 'ssh_scan/client'
require 'ssh_scan/constants'
require 'rspec/mocks'

describe SSHScan::Client do
  context "when connecting as a client" do
    it "should follow a specific sequence on the TCPSocket for connect() operation" do
      server_protocol = "SSH-2.0-server"

      # Override TCPSocket behavior in the name of unit-testing
      io = double("io", puts: nil)
      allow(io).to receive(:puts).and_return(nil)
      allow(io).to receive(:gets).and_return(server_protocol)
      allow(TCPSocket).to receive(:new) { io }

      # Do the client connect action
      client = SSHScan::Client.new("192.168.1.1", 22)
      client.connect

      # Verify the client behaved as expected
      expect(io).to have_received(:puts).with("SSH-2.0-client")
      expect(client.instance_variable_get(:@server_protocol)).to eql(server_protocol)
    end

    it "should follow a specific sequence on the TCPSocket for get_kex_result() operation" do
      server_protocol = "SSH-2.0-server"

      # Override TCPSocket behavior in the name of unit-testing
      io = double("io", puts: nil)
      allow(io).to receive(:puts).and_return(nil)
      allow(io).to receive(:gets).and_return(server_protocol)
      allow(TCPSocket).to receive(:new) { io }

      # Do the client connect action
      client = SSHScan::Client.new("192.168.1.1", 22)
      client.connect

      # Verify the client behaved as expected
      expect(io).to have_received(:puts).with("SSH-2.0-client")
      expect(client.instance_variable_get(:@server_protocol)).to eql(server_protocol)

      # Override more TCPSocket behavior in the name of unit-testing
      allow(io).to receive(:write).and_return(nil)
      allow(io).to receive(:read).and_return(
        "\x00\x00\x03D",
        "\n\x14\x17>>\xD1\xB5r\xBF\xA0jE\x19Y1p\x85\xEE\x00\x00\x00~diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\x00\x00\x00\x0Fssh-rsa,ssh-dss\x00\x00\x00\x9Daes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se\x00\x00\x00\x9Daes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se\x00\x00\x00\x85hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96\x00\x00\x00\x85hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
      allow(io).to receive(:close).and_return(nil)

      # Do the client get_kex_result action
      result = client.get_kex_result

      # Verify the client behaved as expected
      expect(io).to have_received(:write).once.with(SSHScan::Constants::DEFAULT_KEY_INIT_RAW)
      expect(io).to have_received(:read).with(4)
      expect(io).to have_received(:read).with(836)
      expect(io).to have_received(:close).once
      expect(result).to be_kind_of(::Hash)
    end

  end
end
