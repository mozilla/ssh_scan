module SSHScan
  class Authenticator
    attr_reader :config

    def initialize(config)
      @config = config
    end

    def self.from_config_file(config_file)
      opts = YAML.load_file(config_file)
      self.new(opts)
    end

    def valid_token?(token)
      if @config["users"]
        @config["users"].each do |user|
          return true if user["token"] == token
        end
      end

      return false
    end
  end
end
