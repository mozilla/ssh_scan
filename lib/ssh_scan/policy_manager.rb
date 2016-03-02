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

    def missing_policy_encryption
      target_encryption = @result[:encryption_algorithms_client_to_server] | @result[:encryption_algorithms_server_to_client]
      outliers = []
      @policy.encryption.each do |encryption|
        if target_encryption.include?(encryption) == false
          outliers << encryption
        end
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

    def missing_policy_macs
      target_macs = @result[:mac_algorithms_server_to_client] | @result[:mac_algorithms_client_to_server]
      outliers = []

      @policy.macs.each do |mac|
        if target_macs.include?(mac) == false
          outliers << mac
        end
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

    def missing_policy_kex
      target_kex = @result[:key_algorithms]
      outliers = []

      @policy.kex.each do |kex|
        if target_kex.include?(kex) == false
          outliers << kex
        end
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

    def missing_policy_compression
      target_compressions = @result[:compression_algorithms_server_to_client] | @result[:compression_algorithms_client_to_server]
      outliers = []

      @policy.compression.each do |compression|
        if target_compressions.include?(compression) == false
          outliers << compression
        end
      end
      return outliers
    end

    def compliant?
      out_of_policy_encryption.empty? &&
      out_of_policy_macs.empty? &&
      out_of_policy_kex.empty? &&
      out_of_policy_compression.empty? &&
      missing_policy_encryption.empty? &&
      missing_policy_macs.empty? &&
      missing_policy_kex.empty? &&
      missing_policy_compression.empty?
    end

    def recommendations
      recommendations = []

      # Add these items to be compliant
      recommendations << "Add these Key Exchange Algos: #{missing_policy_kex.join(", ")}" unless missing_policy_kex.empty?
      recommendations << "Add these MAC Algos: #{missing_policy_macs.join(", ")}" unless missing_policy_macs.empty?
      recommendations << "Add these Encryption Ciphers: #{missing_policy_encryption.join(", ")}" unless missing_policy_encryption.empty?
      recommendations << "Add these Compression Algos: #{missing_policy_compression.join(", ")}" unless missing_policy_compression.empty?

      # Remove these items to be compliant
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
