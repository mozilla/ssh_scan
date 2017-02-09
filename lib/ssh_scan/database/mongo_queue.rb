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

      # @param [String] a socket we want to scan (Example: "192.168.1.1:22")
      # @return [nil]
      def push(socket)
        @queue_collection.insert_one("socket" => socket, "status" => "pending")
      end

      # @return [FixNum] the number of pending records
      def size
        @queue_collection.find("status" => "pending").count
      end

      # @return [FixNum] truth value if there is any pending record or not
      def empty?
        size.zero?
      end

      # @return [String] a socket we want to scan (Example: "192.168.1.1:22")
      def pop
        res = @queue_collection.find_one_and_update({ "status" => "pending" },
                                        { "$set" => { "status" => "running" }})
        res[:socket]
      end

      # @return [Nil]
      def delete_all
        @queue_collection.delete_many({})
      end
    end
  end
end
