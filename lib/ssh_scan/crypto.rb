require 'openssl'
require 'sshkey'
require 'base64'

module SSHScan
  module Crypto
    class PublicKey
      def initialize(key)
        @key = key
      end

      # Is the current key known to be in our known bad key list
      def bad_key?
        SSHScan::Crypto.bad_public_keys.each do |other_key|
          if self.fingerprint_sha256 == other_key.fingerprint_sha256
            return true
          end
        end

        return false
      end

      def fingerprint_md5
        OpenSSL::Digest::MD5.hexdigest(::Base64.decode64(@key)).scan(/../).join(':')
      end

      def fingerprint_sha1
        OpenSSL::Digest::SHA1.hexdigest(::Base64.decode64(@key)).scan(/../).join(':')
      end

      def fingerprint_sha256
        OpenSSL::Digest::SHA256.hexdigest(::Base64.decode64(@key)).scan(/../).join(':')
      end
    end

    def self.bad_public_keys
      bad_keys = []

      Dir.glob("data/ssh-badkeys/host/*.key").each do |file_path|
        file = File.read(File.expand_path(file_path))
        key = SSHKey.new(file)
        bad_keys << SSHScan::Crypto::PublicKey.new(key.ssh_public_key.split[1])
      end

      return bad_keys
    end

  end
end
