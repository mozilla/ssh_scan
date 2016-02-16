require 'bindata'
require 'string_ext'
require 'json'

module SSHScan
  # SSHv2 KexInit
  class KeyExchangeInit < BinData::Record
    endian :big
    uint32 :packet_length
    uint8 :padding_length
    uint8 :message_code
    string :cookie, :length => 16
    uint32 :kex_algorithms_length
    string :key_algorithms_string, :length => lambda { self.kex_algorithms_length }
    uint32 :server_host_key_algorithms_length
    string :server_host_key_algorithms_string, :length => lambda { self.server_host_key_algorithms_length }
    uint32 :encryption_algorithms_client_to_server_length
    string :encryption_algorithms_client_to_server_string, :length => lambda { self.encryption_algorithms_client_to_server_length }
    uint32 :encryption_algorithms_server_to_client_length
    string :encryption_algorithms_server_to_client_string, :length => lambda { self.encryption_algorithms_server_to_client_length }
    uint32 :mac_algorithms_client_to_server_length
    string :mac_algorithms_client_to_server_string, :length => lambda { self.mac_algorithms_client_to_server_length }
    uint32 :mac_algorithms_server_to_client_length
    string :mac_algorithms_server_to_client_string, :length => lambda { self.mac_algorithms_server_to_client_length }
    uint32 :compression_algorithms_client_to_server_length
    string :compression_algorithms_client_to_server_string, :length => lambda { self.compression_algorithms_client_to_server_length }
    uint32 :compression_algorithms_server_to_client_length
    string :compression_algorithms_server_to_client_string, :length => lambda { self.compression_algorithms_server_to_client_length }
    uint32 :languages_client_to_server_length
    string :languages_client_to_server_string, :length => lambda { self.languages_client_to_server_length }
    uint32 :languages_server_to_client_length
    string :languages_server_to_client_string, :length => lambda { self.languages_server_to_client_length }
    uint8 :kex_first_packet_follows
    uint32 :reserved

    def key_algorithms
      self.key_algorithms_string.split(",")
    end

    def server_host_key_algorithms
      self.server_host_key_algorithms_string.split(",")
    end

    def encryption_algorithms_client_to_server
      self.encryption_algorithms_client_to_server_string.split(",")
    end

    def encryption_algorithms_server_to_client
      self.encryption_algorithms_server_to_client_string.split(",")
    end

    def mac_algorithms_client_to_server
      self.mac_algorithms_client_to_server_string.split(",")
    end

    def mac_algorithms_server_to_client
      self.mac_algorithms_server_to_client_string.split(",")
    end

    def compression_algorithms_client_to_server
      self.compression_algorithms_client_to_server_string.split(",")
    end

    def compression_algorithms_server_to_client
      self.compression_algorithms_client_to_server_string.split(",")
    end

    def languages_client_to_server
      self.languages_client_to_server_string.split(",")
    end

    def languages_server_to_client
      self.languages_server_to_client_string.split(",")
    end

    # Summarize as Hash
    def to_hash
      {
        :key_algorithms => key_algorithms,
        :server_host_key_algorithms => server_host_key_algorithms,
        :encryption_algorithms_client_to_server => encryption_algorithms_client_to_server,
        :encryption_algorithms_server_to_client => encryption_algorithms_server_to_client,
        :mac_algorithms_client_to_server => mac_algorithms_client_to_server,
        :mac_algorithms_server_to_client => mac_algorithms_server_to_client,
        :compression_algorithms_client_to_server => compression_algorithms_client_to_server,
        :compression_algorithms_server_to_client => compression_algorithms_server_to_client,
        :languages_client_to_server => languages_client_to_server,
        :languages_server_to_client => languages_server_to_client,
      }
    end

    # Summarize as JSON
    def to_json
      self.to_hash.to_json
    end
  end
end
