require 'ssh_scan/database/mongo'
require 'ssh_scan/database/sqlite'

module SSHScan
  class Database
    attr_reader :database

    # @param [SSHScan::Database::MongoDb, SSHScan::Database::SQLite] database
    def initialize(database)
      @database = database
    end

    # @param [Hash] opts
    # @return [SSHScan::Database]
    def self.from_hash(opts)
      database_options = opts["database"]

      # Figure out what database object to load
      case database_options["type"]
      when "sqlite"
        database = SSHScan::DB::SQLite.from_hash(database_options)
      when "mongodb"
        database = SSHScan::DB::MongoDb.from_hash(database_options)
      else
        raise "Database type of #{database_options[:type].class} not supported"
      end

      SSHScan::Database.new(database)
    end

    # @param [String] worker_id
    # @param [String] uuid
    # @param [Hash] result
    # @return [Nil]
    def add_scan(worker_id, uuid, result, socket)
      @database.add_scan(worker_id, uuid, result, socket)
      return nil
    end

    # @param [String] uuid
    # @return [Nil]
    def delete_scan(uuid)
      @database.delete_scan(uuid)
    end

    # @return [Nil]
    def delete_all
      @database.delete_all
    end

    # @return [Hash] result
    def find_scan_result(uuid)
      @database.find_scan_result(uuid)
    end

    # @return [Hash] result
    def fetch_cached_result(socket)
      @database.fetch_cached_result(socket)
    end
  end
end
