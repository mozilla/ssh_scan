require 'bindata'
require 'string_ext'
require 'json'

module SSHScan
  # SSHv2 KexInit
  class KeyExchangeInit < BinData::Record
    endian :big
    uint32 :packet_length
    uint8 :padding_length, :initial_value => 4
    uint8 :message_code, :initial_value => 20
    string :cookie_string, :length => 16
    uint32 :kex_algorithms_length
    string :key_algorithms_string, :length => lambda {
      self.kex_algorithms_length
    }
    uint32 :server_host_key_algorithms_length
    string :server_host_key_algorithms_string, :length => lambda {
      self.server_host_key_algorithms_length
    }
    uint32 :encryption_algorithms_client_to_server_length
    string :encryption_algorithms_client_to_server_string, :length => lambda {
      self.encryption_algorithms_client_to_server_length
    }
    uint32 :encryption_algorithms_server_to_client_length
    string :encryption_algorithms_server_to_client_string, :length => lambda {
      self.encryption_algorithms_server_to_client_length
    }
    uint32 :mac_algorithms_client_to_server_length
    string :mac_algorithms_client_to_server_string, :length => lambda {
      self.mac_algorithms_client_to_server_length
    }
    uint32 :mac_algorithms_server_to_client_length
    string :mac_algorithms_server_to_client_string, :length => lambda {
      self.mac_algorithms_server_to_client_length
    }
    uint32 :compression_algorithms_client_to_server_length
    string :compression_algorithms_client_to_server_string, :length => lambda {
      self.compression_algorithms_client_to_server_length
    }
    uint32 :compression_algorithms_server_to_client_length
    string :compression_algorithms_server_to_client_string, :length => lambda {
      self.compression_algorithms_server_to_client_length
    }
    uint32 :languages_client_to_server_length
    string :languages_client_to_server_string, :length => lambda {
      self.languages_client_to_server_length
    }
    uint32 :languages_server_to_client_length
    string :languages_server_to_client_string, :length => lambda {
      self.languages_server_to_client_length
    }
    uint8 :kex_first_packet_follows
    uint32 :reserved
    string :padding_string, :read_length => lambda {
      self.padding_length
    }

    def cookie
      self.cookie_string
    end

    def cookie=(string)
      self.cookie_string = string
    end

    def padding
      self.padding_string
    end

    def padding=(string)
      self.padding_string = string
    end

    def key_algorithms
      self.key_algorithms_string.split(",")
    end

    def parse_string_or_array(data)
      case data
      when String
        string = data
      when Array
        string = data.join(",")
      else
        raise ArgumentError
      end

      return string
    end

    def key_algorithms=(data)
      string = parse_string_or_array(data)
      self.key_algorithms_string = string
      self.kex_algorithms_length = string.size
      recalc_packet_length
    end

    def server_host_key_algorithms
      self.server_host_key_algorithms_string.split(",")
    end

    def server_host_key_algorithms=(data)
      string = parse_string_or_array(data)
      self.server_host_key_algorithms_string = string
      self.server_host_key_algorithms_length = string.size
      recalc_packet_length
    end

    def encryption_algorithms_client_to_server
      self.encryption_algorithms_client_to_server_string.split(",")
    end

    def encryption_algorithms_client_to_server=(data)
      string = parse_string_or_array(data)
      self.encryption_algorithms_client_to_server_string = string
      self.encryption_algorithms_client_to_server_length = string.size
      recalc_packet_length
    end

    def encryption_algorithms_server_to_client
      self.encryption_algorithms_server_to_client_string.split(",")
    end

    def encryption_algorithms_server_to_client=(data)
      string = parse_string_or_array(data)
      self.encryption_algorithms_server_to_client_string = string
      self.encryption_algorithms_server_to_client_length = string.size
      recalc_packet_length
    end

    def mac_algorithms_client_to_server
      self.mac_algorithms_client_to_server_string.split(",")
    end

    def mac_algorithms_client_to_server=(data)
      string = parse_string_or_array(data)
      self.mac_algorithms_client_to_server_string = string
      self.mac_algorithms_client_to_server_length = string.size
      recalc_packet_length
    end

    def mac_algorithms_server_to_client
      self.mac_algorithms_server_to_client_string.split(",")
    end

    def mac_algorithms_server_to_client=(data)
      string = parse_string_or_array(data)
      self.mac_algorithms_server_to_client_string = string
      self.mac_algorithms_server_to_client_length = string.size
      recalc_packet_length
    end

    def compression_algorithms_client_to_server
      self.compression_algorithms_client_to_server_string.split(",")
    end

    def compression_algorithms_client_to_server=(data)
      string = parse_string_or_array(data)
      self.compression_algorithms_client_to_server_string = string
      self.compression_algorithms_client_to_server_length = string.size
      recalc_packet_length
    end

    def compression_algorithms_server_to_client
      self.compression_algorithms_server_to_client_string.split(",")
    end

    def compression_algorithms_server_to_client=(data)
      string = parse_string_or_array(data)
      self.compression_algorithms_server_to_client_string = string
      self.compression_algorithms_server_to_client_length = string.size
      recalc_packet_length
    end

    def languages_client_to_server
      self.languages_client_to_server_string.split(",")
    end

    def languages_client_to_server=(data)
      string = parse_string_or_array(data)
      self.languages_client_to_server_string = string
      self.languages_client_to_server_length = string.size
      recalc_packet_length
    end

    def languages_server_to_client
      self.languages_server_to_client_string.split(",")
    end

    def languages_server_to_client=(data)
      string = parse_string_or_array(data)
      self.languages_server_to_client_string = string
      self.languages_server_to_client_length = string.size
      recalc_packet_length
    end

    def recalc_packet_length
      self.packet_length = self.to_binary_s.size - self.padding_length
    end

    # Summarize as Hash
    # @return [Hash] summary
    def to_hash
      {
        :cookie => self.cookie.hexify,
        :key_algorithms => key_algorithms,
        :server_host_key_algorithms => server_host_key_algorithms,
        :encryption_algorithms_client_to_server =>
          encryption_algorithms_client_to_server,
        :encryption_algorithms_server_to_client =>
          encryption_algorithms_server_to_client,
        :mac_algorithms_client_to_server => mac_algorithms_client_to_server,
        :mac_algorithms_server_to_client => mac_algorithms_server_to_client,
        :compression_algorithms_client_to_server =>
          compression_algorithms_client_to_server,
        :compression_algorithms_server_to_client =>
          compression_algorithms_server_to_client,
        :languages_client_to_server => languages_client_to_server,
        :languages_server_to_client => languages_server_to_client,
      }
    end

    # Generate a {SSHScan::KeyExchangeInit} object from given Ruby hash.
    # @param opts [Hash] options
    # @return [SSHScan::KeyExchangeInit] {SSHScan::KeyExchangeInit}
    #   instance initialized using passed opts
    def self.from_hash(opts)
      kex_init = SSHScan::KeyExchangeInit.new()
      kex_init.cookie = opts[:cookie]
      kex_init.padding = opts[:padding]
      kex_init.key_algorithms = opts[:key_algorithms]
      kex_init.server_host_key_algorithms = opts[:server_host_key_algorithms]
      kex_init.encryption_algorithms_client_to_server =
        opts[:encryption_algorithms_client_to_server]
      kex_init.encryption_algorithms_server_to_client =
        opts[:encryption_algorithms_server_to_client]
      kex_init.mac_algorithms_client_to_server =
        opts[:mac_algorithms_client_to_server]
      kex_init.mac_algorithms_server_to_client =
        opts[:mac_algorithms_server_to_client]
      kex_init.compression_algorithms_client_to_server =
        opts[:compression_algorithms_client_to_server]
      kex_init.compression_algorithms_server_to_client =
        opts[:compression_algorithms_server_to_client]
      kex_init.languages_client_to_server = opts[:languages_client_to_server]
      kex_init.languages_server_to_client = opts[:languages_server_to_client]
      return kex_init
    end

    # Summarize as JSON
    # @return [String] JSON representation for summary hash
    def to_json
      self.to_hash.to_json
    end
  end
end
