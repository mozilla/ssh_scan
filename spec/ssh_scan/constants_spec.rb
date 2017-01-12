require 'spec_helper'
require 'rspec'
require 'ssh_scan/constants'

describe SSHScan::Constants do
  it "should have the right value for DEFAULT_KEY_INIT_RAW" do
    default_key_init_raw =
      "000001640414e33f813f8cdcc6b00a3d852ec1aea4980000001a6\
469666669652d68656c6c6d616e2d67726f7570312d7368613100\
00000f7373682d6473732c7373682d72736100000057616573313\
2382d6362632c336465732d6362632c626c6f77666973682d6362\
632c6165733139322d6362632c6165733235362d6362632c61657\
33132382d6374722c6165733139322d6374722c6165733235362d\
637472000000576165733132382d6362632c336465732d6362632\
c626c6f77666973682d6362632c6165733139322d6362632c6165\
733235362d6362632c6165733132382d6374722c6165733139322\
d6374722c6165733235362d63747200000021686d61632d6d6435\
2c686d61632d736861312c686d61632d726970656d64313630000\
00021686d61632d6d64352c686d61632d736861312c686d61632d\
726970656d64313630000000046e6f6e65000000046e6f6e65000\
000000000000000000000006e05b3b4"
    expect(SSHScan::Constants::DEFAULT_KEY_INIT_RAW.unhexify).to eql(
      default_key_init_raw.unhexify
    )
  end

  it "should have the right values for DEFAULT_KEY_INIT" do
    expect(SSHScan::Constants::DEFAULT_KEY_INIT).to be_kind_of(
      SSHScan::KeyExchangeInit
    )
    expect(SSHScan::Constants::DEFAULT_KEY_INIT.to_binary_s).to eql(
      SSHScan::Constants::DEFAULT_KEY_INIT_RAW.unhexify
    )
  end

  it "should have the right value for DEFAULT_CLIENT_BANNER" do
    default_banner = "SSH-2.0-ssh_scan"
    expect(SSHScan::Constants::DEFAULT_CLIENT_BANNER).to be_kind_of(
      SSHScan::Banner
    )
    expect(SSHScan::Constants::DEFAULT_CLIENT_BANNER.to_s).to eql(
      default_banner
    )
  end

  it "should have the right value for DEFAULT_SERVER_BANNER" do
    default_banner = "SSH-2.0-server"
    expect(SSHScan::Constants::DEFAULT_SERVER_BANNER).to be_kind_of(
      SSHScan::Banner
    )
    expect(SSHScan::Constants::DEFAULT_SERVER_BANNER.to_s).to eql(
      default_banner
    )
  end
end
