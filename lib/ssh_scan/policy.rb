require 'yaml'
require 'logger'

module SSHScan
  class Policy
    attr_reader :name, :kex, :macs, :encryption, :compression,
                :references, :auth_methods, :ssh_version

    def initialize(opts = {})
      @name = opts['name'] || []
      @kex = opts['kex'] || []
      @macs = opts['macs'] || []
      @encryption = opts['encryption'] || []
      @compression = opts['compression'] || []
      @references = opts['references'] || []
      @auth_methods = opts['auth_methods'] || []
      @ssh_version = opts['ssh_version'] || false
      @logger = opts['logger']
    end

    def self.from_file(file)
      opts = YAML.load_file(file)
      self.new(opts)
    end

    def self.from_string(string)
      opts = YAML.load(string)
      self.new(opts)
    end

    # Choose a policy file based on rules
    def self.first_match(result)
      logger = @logger || Logger.new(STDERR)
      policies_dir = File.join(File.dirname(__FILE__), "../../config/policies")
      fallback_file = File.join(policies_dir, "mozilla_modern.yml")
      Dir.glob(policies_dir + "/**/*.yml") do |policy_file|
        next if policy_file == fallback_file
        file = YAML.load_file(policy_file)
        next unless file["rules"]
        logger.info("Matching: #{policy_file}")
        if SSHScan::RuleEngine.matchRuleset(file["rules"], file["ruleset"], result)
          logger.info("Matched: #{policy_file}")
          return policy_file
        end
      end
      logger.info("No matches found, using fallback policy file (#{fallback_file}).")
      return fallback_file
    end
  end
end
