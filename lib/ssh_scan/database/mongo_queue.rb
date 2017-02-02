require 'mongo'

Mongo::Logger.logger.level = ::Logger::FATAL

module SSHScan
  module QueueDB
    class MongoDb
      attr_reader :queue_collection

      def initialize(queue_client)
        @queue_client = queue_client
        @queue_collection = @queue_client[:ssh_scan_queue]
      end

      # Helps us create a SSHScan::DB::MongoDB object with a hash
      def self.from_hash(opts)
        name = opts["queue_db_name"]
        server = opts["server"]
        port = opts["port"]
        socket = server + ":" + port.to_s

        queue_client = Mongo::Client.new([socket], :database => name)
        return SSHScan::QueueDB::MongoDb.new(queue_client)
      end

      # @param [String] socket
      def push(socket)
        @queue_collection.insert_one("socket" => socket, "status" => "pending")
      end

      def size
        @queue_collection.find("socket" => socket, "status" => "pending").count
      end

      def empty?
        size.zero?
      end

      def pop
        @queue_collection.find_one_and_update({ "socket" => socket, "status" => "pending" },
                                        { "$set" => { "status" => "running" }})
      end

      def delete_all
        @queue_collection.delete_many({})
      end
    end
  end
end
