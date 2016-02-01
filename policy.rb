module SSH
  class IntermediatePolicy
    def name
      self.class.to_s
    end

    def macs
      ["hmac-sha2-512","hmac-sha2-256"]
    end

    def encryption
      ["aes256-ctr","aes192-ctr","aes128-ctr"]
    end

    def kexs
      ["diffie-hellman-group-exchange-sha256"]
    end
  end

  class PolicyManager
    def initialize(result, policy)
      @policy = policy
      @result = result
    end

    def out_of_policy_encryption
      target_encryption = @result[:encryption_algorithms_client_to_server] | @result[:encryption_algorithms_server_to_client]
      outliers = []
      target_encryption.each do |target_enc|
        outliers << target_enc unless @policy.encryption.include?(target_enc)
      end
      return outliers
    end

    def out_of_policy_macs
      target_macs = @result[:mac_algorithms_server_to_client] | @result[:mac_algorithms_client_to_server]
      outliers = []
      target_macs.each do |target_mac|
        outliers << target_mac unless @policy.macs.include?(target_mac)
      end
      return outliers
    end

    def out_of_policy_kex
      target_kexs = @result[:key_algorithms]
      outliers = []
      target_kexs.each do |target_kex|
        outliers << target_kex unless @policy.kexs.include?(target_kex)
      end
      return outliers
    end

    def compliant?
      out_of_policy_encryption.empty? &&
      out_of_policy_macs.empty? &&
      out_of_policy_kex.empty?
    end

    def recommendations
      recommendations = []
      recommendations << "Remove these Key Exchange Algos: #{out_of_policy_kex.join(", ")}" unless out_of_policy_kex.empty?
      recommendations << "Remove these MAC Algos: #{out_of_policy_macs.join(", ")}" unless out_of_policy_macs.empty?
      recommendations << "Remove these Encryption Ciphers: #{out_of_policy_encryption.join(", ")}" unless out_of_policy_encryption.empty?
      return recommendations
    end

    def compliance_results
      {
        :policy => @policy.name,
        :compliant => compliant?,
        :recommendations => recommendations
      }
    end
  end
end
