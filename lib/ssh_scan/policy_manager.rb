module SSHScan
  # Policy management methods, compliance checking and recommendations.
  class PolicyManager
    def initialize(result, policy)
      @policy = policy
      @result = result
    end

    def out_of_policy_encryption
      return [] if @policy.encryption.empty?
      target_encryption =
        @result.encryption_algorithms_client_to_server |
        @result.encryption_algorithms_server_to_client
      outliers = []
      target_encryption.each do |target_enc|
        outliers << target_enc unless @policy.encryption.include?(target_enc)
      end
      return outliers
    end

    def missing_policy_encryption
      return [] if @policy.encryption.empty?
      target_encryption =
        @result.encryption_algorithms_client_to_server |
        @result.encryption_algorithms_server_to_client
      outliers = []
      @policy.encryption.each do |encryption|
        if target_encryption.include?(encryption) == false
          outliers << encryption
        end
      end
      return outliers
    end

    def out_of_policy_macs
      return [] if @policy.macs.empty?
      target_macs =
        @result.mac_algorithms_server_to_client |
        @result.mac_algorithms_client_to_server
      outliers = []
      target_macs.each do |target_mac|
        outliers << target_mac unless @policy.macs.include?(target_mac)
      end
      return outliers
    end

    def missing_policy_macs
      return [] if @policy.macs.empty?
      target_macs =
        @result.mac_algorithms_server_to_client |
        @result.mac_algorithms_client_to_server
      outliers = []

      @policy.macs.each do |mac|
        if target_macs.include?(mac) == false
          outliers << mac
        end
      end
      return outliers
    end

    def out_of_policy_kex
      return [] if @policy.kex.empty?
      target_kexs = @result.key_algorithms
      outliers = []
      target_kexs.each do |target_kex|
        outliers << target_kex unless @policy.kex.include?(target_kex)
      end
      return outliers
    end

    def missing_policy_kex
      return [] if @policy.kex.empty?
      target_kex = @result.key_algorithms
      outliers = []

      @policy.kex.each do |kex|
        if target_kex.include?(kex) == false
          outliers << kex
        end
      end
      return outliers
    end

    def out_of_policy_compression
      return [] if @policy.compression.empty?
      target_compressions =
        @result.compression_algorithms_server_to_client |
        @result.compression_algorithms_client_to_server
      outliers = []
      target_compressions.each do |target_compression|
        outliers << target_compression unless
          @policy.compression.include?(target_compression)
      end
      return outliers
    end

    def missing_policy_compression
      return [] if @policy.compression.empty?
      target_compressions =
        @result.compression_algorithms_server_to_client |
        @result.compression_algorithms_client_to_server
      outliers = []

      @policy.compression.each do |compression|
        if target_compressions.include?(compression) == false
          outliers << compression
        end
      end
      return outliers
    end

    def out_of_policy_auth_methods
      return [] if @policy.auth_methods.empty?
      return [] if @result.auth_methods.empty?
      target_auth_methods = @result.auth_methods
      outliers = []

      if not @policy.auth_methods.empty?
        target_auth_methods.each do |auth_method|
          if not @policy.auth_methods.include?(auth_method)
            outliers << auth_method
          end
        end
      end
      return outliers
    end

    def out_of_policy_ssh_version
      return false if @policy.ssh_version.nil?
      target_ssh_version = @result.ssh_version
      if @policy.ssh_version
        if target_ssh_version < @policy.ssh_version
          return true
        end
      end
      return false
    end

    def compliant?
      out_of_policy_encryption.empty? &&
      out_of_policy_macs.empty? &&
      out_of_policy_kex.empty? &&
      out_of_policy_compression.empty? &&
      missing_policy_encryption.empty? &&
      missing_policy_macs.empty? &&
      missing_policy_kex.empty? &&
      missing_policy_compression.empty? &&
      out_of_policy_auth_methods.empty? &&
      !out_of_policy_ssh_version
    end

    def recommendations
      recommendations = []

      # Add these items to be compliant
      if missing_policy_kex.any?
        recommendations << "Add these key exchange algorithms: \
#{missing_policy_kex.join(",")}"
      end

      if missing_policy_macs.any?
        recommendations << "Add these MAC algorithms: \
#{missing_policy_macs.join(",")}"
      end

      if missing_policy_encryption.any?
        recommendations << "Add these encryption ciphers: \
#{missing_policy_encryption.join(",")}"
      end

      if missing_policy_compression.any?
        recommendations << "Add these compression algorithms: \
#{missing_policy_compression.join(",")}"
      end

      # Remove these items to be compliant
      if out_of_policy_kex.any?
        recommendations << "Remove these key exchange algorithms: \
#{out_of_policy_kex.join(", ")}"
      end

      if out_of_policy_macs.any?
        recommendations << "Remove these MAC algorithms: \
#{out_of_policy_macs.join(", ")}"
      end

      if out_of_policy_encryption.any?
        recommendations << "Remove these encryption ciphers: \
#{out_of_policy_encryption.join(", ")}"
      end

      if out_of_policy_compression.any?
        recommendations << "Remove these compression algorithms: \
#{out_of_policy_compression.join(", ")}"
      end

      if out_of_policy_auth_methods.any?
        recommendations << "Remove these authentication methods: \
#{out_of_policy_auth_methods.join(", ")}"
      end

      # Update these items to be compliant
      if out_of_policy_ssh_version
        recommendations << "Update your ssh version to: #{@policy.ssh_version}"
      end

      return recommendations
    end

    def compliance_results
      {
        :policy => @policy.name,
        :compliant => compliant?,
        :recommendations => recommendations,
        :references => @policy.references,
      }
    end
  end
end
