require 'yaml'

module SSHScan
  class EncryptionCipher
    def initialize(cipher_string)
      @cipher_string = cipher_string
    end

    def to_s
      @cipher_string
    end

    def base_cipher
      @cipher_string.split("@").first
    end

    def ==(other_cipher)
      self.base_cipher == other_cipher.base_cipher
    end
  end
end