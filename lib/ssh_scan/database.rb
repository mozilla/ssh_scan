# API Databases
# require 'ssh_scan/database/mongo'
# require 'ssh_scan/database/sqlite'

module SSHScan
  class Database
    attr_reader :database, :username, :password, :server, :port

    def initialize(opts = {})
      @database = opts[:database] # SSHScan::Database::MongoDb, SSHScan::Database::SQLite, etc.
      @username = opts[:username]
      @password = opts[:password]
      @file = opts[:file]
      @server = opts[:server]
      @port = opts[:port]
    end

    def add_scan(worker_id, uuid, result)
      @database.add_scan(worker_id, uuid, result)
    end

    def delete_scan(uuid)
      @database.delete_scan(uuid)
    end

    def delete_all
      @database.delete_all
    end

    def find_scan_result(uuid)
      @database.find_scan_result(uuid)
    end 
  end
end
