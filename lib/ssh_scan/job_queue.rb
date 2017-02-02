require 'ssh_scan/database/mongo_queue'
require 'ssh_scan/database/sqlite_queue'

module SSHScan
  class JobQueue
    def initialize(queue_database)
      @queue = queue_database
    end

    # @param [Hash] opts
    # @return [SSHScan::Database]
    def self.from_hash(opts)
      database_options = opts["database"]

      # Figure out what database object to load
      case database_options["type"]
      when "sqlite"
        queue_database = SSHScan::QueueDB::SQLite.from_hash(database_options)
      when "mongodb"
        queue_database = SSHScan::QueueDB::MongoDb.from_hash(database_options)
      else
        raise "Database type of #{database_options[:type].class} not supported"
      end

      SSHScan::JobQueue.new(queue_database)
    end

    # @param [String] a socket we want to scan (Example: "192.168.1.1:22")
    # @return [nil]
    def add(socket)
      @queue.push(socket)
    end

    # @return [String] a socket we want to scan (Example: "192.168.1.1:22")
    def next
      return nil if @queue.empty?
      @queue.pop
    end

    # @return [FixNum] the number of jobs in the JobQueue
    def size
      @queue.size
    end

    # @return [Nil]
    def delete_all
      @queue.delete_all
    end
  end
end
