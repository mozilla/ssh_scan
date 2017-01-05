# API Databases
require 'ssh_scan/database/mongo'
require 'ssh_scan/database/sqlite'

module SSHScan
  class DatabaseConfig
    def initialize(opts = {})
      @@db_type = if !opts || opts.empty?
                   'sqlite'
                 else
                   opts['database']['type']
                 end
    end

    def self.from_config_file
      @db_path = File.join(Dir.pwd, '/config/database/database_config.yml')
      db_opts = YAML.load_file(@db_path)
      SSHScan::DatabaseConfig.new(db_opts)
      if @@db_type.eql? 'mongodb'
        return SSHScan::Database::MongoDb.from_config_file(@db_path)
      elsif @@db_type.eql? 'sqlite'
        return SSHScan::Database::SQLite.from_config_file(@db_path)
      end
    end
  end
end
