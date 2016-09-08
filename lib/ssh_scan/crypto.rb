require 'openssl'

module SSHScan
  module Crypto
    class PublicKey
      def initialize(key)
        @key = key
        @supported = check_supported
        if @key.is_a?(OpenSSL::PKey::RSA)
          @data_string = OpenSSL::ASN1::Sequence([
           OpenSSL::ASN1::Integer.new(@key.public_key.n),
           OpenSSL::ASN1::Integer.new(@key.public_key.e)
          ])
        end
      end

      def check_supported
        @key and @key.is_a?(OpenSSL::PKey::RSA)
      end

      def is_supported?
        @supported
      end

      def fingerprint_md5
        OpenSSL::Digest::MD5.hexdigest(@data_string.to_der).scan(/../).join(':')
      end

      def fingerprint_sha1
        OpenSSL::Digest::SHA1.hexdigest(@data_string.to_der).scan(/../).join(':')
      end

      def fingerprint_sha256
        OpenSSL::Digest::SHA256.hexdigest(@data_string.to_der).scan(/../).join(':')
      end
    end
  end
end
