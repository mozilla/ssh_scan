require 'yaml'

module SSHScan
  # Policy methods that deal with key exchange, macs, encryption methods,
  # compression methods and more.
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
      @ssh_version = opts['ssh_version'] || nil
    end

    # Generate a {SSHScan::Policy} object from YAML file.
    # @param file [String] filepath
    # @return [SSHScan::Policy] new instance with parameters loaded
    #   from YAML file
    def self.from_file(file)
      opts = YAML.load_file(file)
      self.new(opts)
    end

    # Generate a {SSHScan::Policy} object from YAML string.
    # @param string [String] YAML string
    # @return [SSHScan::Policy] new instance with parameters loaded
    #   from given string
    def self.from_string(string)
      opts = YAML.load(string)
      self.new(opts)
    end
  end
end
