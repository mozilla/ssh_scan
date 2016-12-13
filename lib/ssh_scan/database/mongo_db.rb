require 'mongo'

Mongo::Logger.logger.level = ::Logger::FATAL

module   SSHScan
  module Database
    class MongoDb
      def initialize(opts = {})
        name = opts["database"]["name"]
        socket = "#{opts["database"]["server"]}:#{opts["database"]["port"]}"
        @db = Mongo::Client.new([socket], :database => name)
        @scans = @db[:scans]
      end

      def self.from_config_file(file_string)
        opts = YAML.load_file(file_string)
        SSHScan::Database::MongoDb.new(opts)
      end

      def add_scan(worker_id, uuid, result)
        @scans.insert_one("uuid" => uuid, "scan" => result,
                          "worker_id" => worker_id, "scanned_on" => Time.now)
      end

      def delete_scan(uuid)
        @scans.delete_one(:uuid => uuid)
      end

      def delete_all
        @scans.delete_many({})
      end

      def find_scan_result(uuid)
        @scans.find(:uuid => uuid).each do |doc|
          return doc[:scan].to_json
        end
      end
    end
  end
end
