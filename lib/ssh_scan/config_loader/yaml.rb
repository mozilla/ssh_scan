require 'yaml'

module SSHScan
  module ConfigLoader
    class Yaml
      def initialize(config, class_name = nil, mode = 'file', logger = nil)
        @opts = case mode
          when "file" then YAML.load_file(config)
          when "string" then YAML.load(config)
        end
        @logger = logger || Logger.new(STDOUT)
        @class_name = class_name ? class_name.name : ""
        @good_opts = loadGoodOpts
      end

      def opts
        @opts
      end

      def checkedOpts
        unless @good_opts.nil?
          allowed = @good_opts["allowed"]
          error_count = 0
          retrieved_opts = opts
          retrieved_opts.each do |key, value|
            unless allowed.include?(key)
              @logger.error("attribute not allowed: #{key}")
              error_count += 1
            end
          end
          @logger.fatal("error count for #{@class_name} configuration: #{error_count}") if error_count > 0
        end
        @opts
      end

      def loadGoodOpts

        # This function loads the appropriate yml file that lists the attributes allowed
        # for a configuration file associated with a class. For example, suppose policy
        # configuration files (SSHScan::Policy) can only have attributes a, b, c then
        # we can have a whitelist at config/loader_configs
        ###########
        # allowed:
        # - a
        # - b
        # - c
        ###########
        # Our requirement is one such whitelist per class, so a good way to name such files
        # is just downcasing their classnames. Examples of class - whitelist filenames:
        # SSHScan::Authenticator => config/loader_configs/authenticator.yml
        # SSHScan::Policy        => config/loader_configs/policy.yml
        # SSHScan::A::B::C       => config/loader_configs/a_b_c.yml
        # and so on ... (SSHScan:: is redundant in these classnames, so let's not have it)

        unless @class_name.nil?
          configs_dir = File.join(File.dirname(__FILE__), "../../../config/loader_configs")
          reduced_class_name = @class_name.downcase.split("::").join("_")
          # 'sshscan_' in every class name is redundant
          reduced_class_name.gsub!("sshscan_", "")
          possible_file = File.expand_path(File.join(configs_dir, "#{reduced_class_name}.yml"))
          begin
            config = YAML.load_file(possible_file)
          rescue Errno::ENOENT
            @logger.error("File #{possible_file} does not exist.")
          else
            return config
          end
        end
      end
    end
  end
end
