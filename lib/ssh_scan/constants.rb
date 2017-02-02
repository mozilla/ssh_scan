require 'string_ext'
require 'ssh_scan/banner'
require 'ssh_scan/protocol'

module SSHScan
  # House all the constants we need.
  module Constants
    DEFAULT_CLIENT_BANNER = SSHScan::Banner.new("SSH-2.0-ssh_scan")
    DEFAULT_SERVER_BANNER = SSHScan::Banner.new("SSH-2.0-server")

    default_key_init_opts = {
      :cookie => "e33f813f8cdcc6b00a3d852ec1aea498".unhexify,
      :padding => "6e05b3b4".unhexify,
      :key_algorithms => ["diffie-hellman-group1-sha1"],
      :server_host_key_algorithms => ["ssh-dss","ssh-rsa"],
      :encryption_algorithms_client_to_server => [
        "aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc",
        "aes128-ctr","aes192-ctr","aes256-ctr"
      ],
      :encryption_algorithms_server_to_client => [
        "aes128-cbc","3des-cbc","blowfish-cbc","aes192-cbc","aes256-cbc",
        "aes128-ctr","aes192-ctr","aes256-ctr"
      ],
      :mac_algorithms_client_to_server => [
        "hmac-md5","hmac-sha1","hmac-ripemd160"
      ],
      :mac_algorithms_server_to_client => [
        "hmac-md5","hmac-sha1","hmac-ripemd160"
      ],
      :compression_algorithms_client_to_server => ["none"],
      :compression_algorithms_server_to_client => ["none"],
      :languages_client_to_server => [],
      :languages_server_to_client => [],
    }

    DEFAULT_KEY_INIT = SSHScan::KeyExchangeInit.from_hash(default_key_init_opts)

    DEFAULT_KEY_INIT_RAW =
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
000000000000000000000006e05b3b4".freeze

    CONTRIBUTE_JSON = {
      :name => "ssh_scan api",
      :description => "An api for performing ssh compliance \
and policy scanning",
      :repository => {
        :url => "https://github.com/mozilla/ssh_scan",
        :tests => "https://travis-ci.org/mozilla/ssh_scan",
      },
      :participate => {
        :home => "https://github.com/mozilla/ssh_scan",
        :docs => "https://github.com/mozilla/ssh_scan",
        :irc => "irc://irc.mozilla.org/#infosec",
        :irc_contacts => [
          "claudijd",
          "pwnbus",
          "kang",
        ],
        :gitter => "https://gitter.im/mozilla-ssh_scan/Lobby",
        :gitter_contacts => [
          "claudijd",
          "pwnbus",
          "kang",
          "jinankjain",
          "agaurav77"
        ],
      },
      :bugs => {
        :list => "https://github.com/mozilla/ssh_scan/issues",
      },
      :keywords => [
        "ruby",
        "sinatra",
      ],
      :urls => {
        :dev => "https://sshscan.rubidus.com",
      }
    }.freeze
  end
end
