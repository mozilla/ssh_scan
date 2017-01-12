require 'mongo'

Mongo::Logger.logger.level = ::Logger::FATAL

module SSHScan
  module DB
    class MongoDb
      attr_reader :collection

      def initialize(client)
        @client = client
        @collection = @client[:ssh_scan]
      end

      # Helps us create a SSHScan::DB::MongoDB object with a hash
      def self.from_hash(opts)
        name = opts["name"]
        server = opts["server"]
        port = opts["port"]
        socket = server + ":" + port.to_s

        client = Mongo::Client.new([socket], :database => name)
        return SSHScan::DB::MongoDb.new(client)
      end

      # @param [String] worker_id
      # @param [String] uuid
      # @param [Hash] result
      def add_scan(worker_id, uuid, result)
        @collection.insert_one("uuid" => uuid, "scan" => result,
                          "worker_id" => worker_id, "scanned_on" => Time.now)
      end

      def delete_scan(uuid)
        @collection.delete_one(:uuid => uuid)
      end

      def delete_all
        @collection.delete_many({})
      end

      # LEFT OFF HERE: the results of this method should be the exact same format as with SQLite
      def find_scan_result(uuid)
        @collection.find(:uuid => uuid).each do |doc|
          return doc[:scan].to_hash
        end
        
        return nil
      end
    end
  end
end
