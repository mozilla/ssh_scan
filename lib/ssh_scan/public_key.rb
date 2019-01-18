require 'openssl'
require 'sshkey'
require 'base64'

module SSHScan
  # All cryptography related methods.
  module Crypto
    # House methods helpful in analysing SSH public keys.
    class PublicKey
      def initialize(key_string)
        @key_string = key_string
      end

      def valid?
        SSHKey.valid_ssh_public_key?(@key_string)
      end

      def type
        if @key_string.start_with?("ssh-rsa")
          return "rsa"
        elsif @key_string.start_with?("ssh-dss")
          return "dsa"
        elsif @key_string.start_with?("ecdsa-sha2-nistp256")
          return "ecdsa-sha2-nistp256"
        elsif @key_string.start_with?("ssh-ed25519")
          return "ed25519"
        else
          return "unknown"
        end 
      end

      def length
        SSHKey.ssh_public_key_bits(@key_string)
      end

      def fingerprint_md5
        SSHKey.fingerprint(@key_string)
      end

      def fingerprint_sha1
        SSHKey.sha1_fingerprint(@key_string)
      end

      def fingerprint_sha256
        # We're translating this to hex because the SSHKEY default isn't as useful for comparing with SSHFP records
        Base64.decode64(SSHKey.sha256_fingerprint(@key_string)).hexify(:delim => ":")
      end

      def to_hash
        {
          self.type => {
            "raw" => @key_string,
            "length" => self.length,
            "fingerprints" => {
              "md5" => self.fingerprint_md5,
              "sha1" => self.fingerprint_sha1,
              "sha256" => self.fingerprint_sha256
            }
          }
        }
      end
    end
  end
end
