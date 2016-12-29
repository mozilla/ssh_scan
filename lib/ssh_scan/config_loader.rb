require 'logger'

require 'ssh_scan/config_loader/yaml'

module SSHScan
  module ConfigLoader
    def self.load(config, class_name = nil, logger = nil)
      ext = File.extname(config) if config
      case config
      when File
        if ext == ".yml"
          loaded_config = SSHScan::ConfigLoader::Yaml.new(config, class_name, 'file', logger)
        else
          raise "no support for this kind of file yet: #{ext}"
        end
      when String
        # Change for other formats when they are available?
        if config.include?(".yml") && File.exist?(config)
          if ext == ".yml"
            loaded_config = SSHScan::ConfigLoader::Yaml.new(config, class_name, 'file', logger)
          else
            raise "no support for this kind of file yet: #{ext}"
          end
        else
          if !!YAML.load(config)
            loaded_config = SSHScan::ConfigLoader::Yaml.new(config, class_name, 'string', logger)
          else
            raise "unknown syntax"
          end
        end
      else
        raise "unsupported config object type #{config.class}"
      end
      return loaded_config.checkedOpts
    end
  end
end
