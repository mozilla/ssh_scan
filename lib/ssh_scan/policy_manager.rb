module SSHScan
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
        outliers << target_kex unless @policy.kex.include?(target_kex)
      end
      return outliers
    end

    def out_of_policy_compression
      target_compressions = @result[:compression_algorithms_server_to_client] | @result[:compression_algorithms_client_to_server]
      outliers = []
      target_compressions.each do |target_compression|
        outliers << target_compression unless @policy.compression.include?(target_compression)
      end
      return outliers
    end

    def compliant?
      out_of_policy_encryption.empty? &&
      out_of_policy_macs.empty? &&
      out_of_policy_kex.empty? &&
      out_of_policy_compression.empty?
    end

    def recommendations
      recommendations = []
      recommendations << "Remove these Key Exchange Algos: #{out_of_policy_kex.join(", ")}" unless out_of_policy_kex.empty?
      recommendations << "Remove these MAC Algos: #{out_of_policy_macs.join(", ")}" unless out_of_policy_macs.empty?
      recommendations << "Remove these Encryption Ciphers: #{out_of_policy_encryption.join(", ")}" unless out_of_policy_encryption.empty?
      recommendations << "Remove these Compression Algos: #{out_of_policy_compression.join(", ")}" unless out_of_policy_compression.empty?
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
