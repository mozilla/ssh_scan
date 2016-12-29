require 'ssh_scan/config_loader'

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
    end

    def self.from_file(file)
      opts = SSHScan::ConfigLoader.load(file, self)
      self.new(opts)
    end

    def self.from_string(string)
      opts = SSHScan::ConfigLoader.load(string, self)
      self.new(opts)
    end
  end
end
