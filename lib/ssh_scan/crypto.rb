require 'openssl'

module SSHScan
  module Crypto
    class PublicKey
      def initialize(key)
        @key = key
      end

      def fingerprint_md5
        OpenSSL::Digest::MD5.hexdigest(Base64.decode64(@key)).scan(/../).join(':')
      end

      def fingerprint_sha1
        OpenSSL::Digest::SHA1.hexdigest(Base64.decode64(@key)).scan(/../).join(':')
      end

      def fingerprint_sha256
        OpenSSL::Digest::SHA256.hexdigest(Base64.decode64(@key)).scan(/../).join(':')
      end
    end
  end
end
