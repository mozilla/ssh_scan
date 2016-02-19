require 'yaml'

module SSHScan
  class Policy
    attr_reader :name, :kex, :macs, :encryption, :compression

    def initialize(opts = {})
      @name = opts['name'] || []
      @kex = opts['kex'] || []
      @macs = opts['macs'] || []
      @encryption = opts['encryption'] || []
      @compression = opts['compression'] || []
    end

    def self.from_file(file)
      opts = YAML.load_file(file)
      self.new(opts)
    end

    def self.from_string(string)
      opts = YAML.load(string)
      self.new(opts)
    end
  end
end
